import {
  addressKey,
  ApiRequestError,
  collectTouchedFunctions,
  createGhidraClient,
  normalizeTarget,
  type ExportResponse,
  type GhidraClient,
  type SavedServer,
  type SseConnectionState,
  type SseFrame,
  type StatusResponse,
  type VersionDetail,
  type VersionSummary,
} from '#lib/ghidra-api.ts';
import { SvelteDate, SvelteMap, SvelteSet } from 'svelte/reactivity';

export type SessionPhase =
  'disconnected' | 'connecting' | 'analyzing' | 'ready' | 'error' | 'recovery_required' | 'stopped';

export type LastVersionEvent = {
  version: number;
  operation: string;
  addresses: string[];
};

export type GhidraSessionOptions = {
  onServerReady?: (server: SavedServer) => void;
};

/** Owns one ghidraMCP server connection, health polling, SSE stream, and version cache. */
export class GhidraSession {
  phase = $state<SessionPhase>('disconnected');
  phaseDetail = $state<string | null>(null);
  client = $state<GhidraClient | null>(null);
  rawTarget = $state('');
  token = $state('');
  status = $state<StatusResponse | null>(null);
  versions = $state<VersionSummary[]>([]);
  versionCache = new SvelteMap<number, VersionDetail>();

  sseState = $state<SseConnectionState>('disconnected');
  lastEvent = $state<{ event: string; at: string } | null>(null);
  lastVersionEvent = $state<LastVersionEvent | null>(null);

  actionError = $state<string | null>(null);
  exportNotice = $state<ExportResponse | null>(null);
  exportLoading = $state(false);
  shutdownLoading = $state(false);

  touchedAddresses = $derived(
    new SvelteSet(collectTouchedFunctions(this.versions).map((fn) => addressKey(fn.address))),
  );

  statusBadgeColor = $derived.by((): 'green' | 'yellow' | 'red' | 'white' => {
    if (this.phase === 'ready' && this.sseState === 'connected') return 'green';
    if (this.phase === 'ready' || this.phase === 'analyzing' || this.phase === 'connecting') return 'yellow';
    if (this.phase === 'error' || this.phase === 'recovery_required') return 'red';
    return 'white';
  });

  statusBadgeText = $derived.by(() => {
    if (this.phase === 'ready') {
      if (this.sseState === 'connected') return 'LIVE SSE';
      if (this.sseState === 'reconnecting') return 'RECONNECTING';
      if (this.sseState === 'auth_error') return 'AUTH ERROR';
      return 'READY';
    }
    if (this.phase === 'analyzing') return 'ANALYZING';
    if (this.phase === 'connecting') return 'CONNECTING';
    if (this.phase === 'recovery_required') return 'RECOVERY REQUIRED';
    if (this.phase === 'stopped') return 'STOPPED';
    if (this.phase === 'error') return 'UNREACHABLE';
    return 'DISCONNECTED';
  });

  canShutdown = $derived(
    Boolean(this.client) && (this.phase === 'ready' || this.phase === 'analyzing') && !this.shutdownLoading,
  );

  private activeConnection: AbortController | null = null;
  private inFlightVersions = new SvelteMap<number, Promise<VersionDetail | null>>();
  private refreshSeq = 0;
  private needsReconnectRefresh = false;
  private onServerReady?: (server: SavedServer) => void;

  constructor(options?: GhidraSessionOptions) {
    this.onServerReady = options?.onServerReady;
  }

  connect(raw: string, token = ''): string | null {
    this.disconnect();
    const trimmed = raw.trim();
    this.rawTarget = trimmed;
    this.token = token;
    this.actionError = null;
    this.exportNotice = null;
    this.exportLoading = false;
    this.shutdownLoading = false;
    this.lastVersionEvent = null;
    this.status = null;
    this.versions = [];
    this.lastEvent = null;
    this.versionCache.clear();
    this.needsReconnectRefresh = false;
    this.refreshSeq++;

    let normalized: string;
    try {
      normalized = normalizeTarget(trimmed);
    } catch (error) {
      this.client = null;
      this.phase = 'error';
      this.phaseDetail = error instanceof Error ? error.message : 'Invalid target.';
      return null;
    }

    const controller = new AbortController();
    this.activeConnection = controller;
    const nextClient = createGhidraClient(normalized, token, controller.signal);
    this.client = nextClient;
    this.phase = 'connecting';
    this.phaseDetail = `Connecting to ${normalized}...`;

    void this.bootConnection(nextClient, controller.signal, trimmed);
    return normalized;
  }

  disconnect() {
    this.activeConnection?.abort();
    this.activeConnection = null;
    this.inFlightVersions.clear();
    this.sseState = 'disconnected';
  }

  dispose() {
    this.disconnect();
  }

  ensureVersionDetail = async (version: number): Promise<VersionDetail | null> => {
    const cached = this.versionCache.get(version);
    if (cached) return cached;
    if (!this.client) return null;

    const existing = this.inFlightVersions.get(version);
    if (existing) return existing;

    const signal = this.activeConnection?.signal;
    const promise = this.client
      .version(version, signal)
      .then((res) => {
        this.versionCache.set(version, res.version);
        return res.version;
      })
      .catch((error) => {
        if (error instanceof DOMException && error.name === 'AbortError') return null;
        throw error;
      })
      .finally(() => {
        this.inFlightVersions.delete(version);
      });

    this.inFlightVersions.set(version, promise);
    return promise;
  };

  async exportSnapshot() {
    if (!this.client) return;
    this.exportLoading = true;
    this.actionError = null;
    this.exportNotice = null;
    try {
      this.exportNotice = await this.client.exportSnapshot(this.activeConnection?.signal);
    } catch (error) {
      this.actionError =
        error instanceof ApiRequestError && error.status === 401
          ? 'Export requires a valid write (--rw-token) token.'
          : error instanceof Error
            ? error.message
            : 'Export failed.';
    } finally {
      this.exportLoading = false;
    }
  }

  async shutdown() {
    if (!this.client) return;
    this.shutdownLoading = true;
    this.actionError = null;
    try {
      await this.client.shutdown(this.activeConnection?.signal);
      this.disconnect();
      this.phase = 'stopped';
      this.phaseDetail = 'Server shutdown initiated cleanly.';
    } catch (error) {
      this.actionError =
        error instanceof ApiRequestError && error.status === 401
          ? 'Shutdown requires a valid write (--rw-token) token.'
          : error instanceof Error
            ? error.message
            : 'Shutdown failed.';
    } finally {
      this.shutdownLoading = false;
    }
  }

  private async refreshSession(connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    const seq = ++this.refreshSeq;
    const prevStatus = this.status;
    const [nextStatus, nextVersions] = await Promise.all([connClient.status(signal), connClient.versions(signal)]);
    if (signal.aborted || seq !== this.refreshSeq) return;
    if (
      prevStatus &&
      (nextStatus.binary_sha256 !== prevStatus.binary_sha256 || nextStatus.version < prevStatus.version)
    ) {
      this.versionCache.clear();
      this.inFlightVersions.clear();
    }
    this.status = nextStatus;
    this.versions = nextVersions.versions;
    this.onServerReady?.({
      raw: rawTarget,
      baseUrl: connClient.baseUrl,
      label: nextStatus.binary_name,
    });
  }

  private handleSseFrame(frame: SseFrame, connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    this.lastEvent = { event: frame.event, at: new SvelteDate().toLocaleTimeString() };
    if (frame.event === 'checkpoint_saved') {
      const ver = Number(frame.data.version);
      if (Number.isFinite(ver)) this.versionCache.delete(ver);
    }
    if (frame.event === 'version_created') {
      const ver = Number(frame.data.version);
      const operation = typeof frame.data.operation === 'string' ? frame.data.operation : '';
      const rawFns = Array.isArray(frame.data.functions) ? frame.data.functions : [];
      const addresses = rawFns
        .map((item) =>
          item && typeof item === 'object' && 'function_address' in item
            ? String((item as { function_address: unknown }).function_address ?? '')
            : '',
        )
        .filter(Boolean);
      if (Number.isFinite(ver)) {
        this.lastVersionEvent = { version: ver, operation, addresses };
      }
    }
    if (frame.event === 'status') {
      const sseVer = Number(frame.data.version);
      const mustRefresh = this.needsReconnectRefresh;
      this.needsReconnectRefresh = false;
      if (
        this.phase === 'ready' &&
        this.status &&
        !mustRefresh &&
        Number.isFinite(sseVer) &&
        sseVer === this.status.version
      ) {
        return;
      }
    }
    if (frame.event === 'status' || frame.event === 'version_created' || frame.event === 'checkpoint_saved') {
      void this.refreshSession(connClient, signal, rawTarget).catch((error) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) {
          this.actionError = error instanceof Error ? error.message : 'Failed to refresh after SSE update.';
        }
      });
    }
  }

  private async bootConnection(connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    try {
      while (!signal.aborted) {
        try {
          const health = await connClient.health(signal);
          if (signal.aborted) return;
          if (health.status === 'analyzing') {
            this.phase = 'analyzing';
            this.phaseDetail = 'Ghidra is importing and analyzing the binary...';
            if (!(await sleepAbortable(1500, signal))) return;
            continue;
          }
          if (health.status === 'recovery_required') {
            this.phase = 'recovery_required';
            this.phaseDetail = health.error || 'Restart the ghidraMCP server to recover the workspace.';
            return;
          }
          if (health.status === 'error' || !health.ok) {
            this.phase = 'error';
            this.phaseDetail = health.error || `Server reported status: ${health.status}`;
            return;
          }
          break;
        } catch (error) {
          if (signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) return;
          if (error instanceof ApiRequestError && error.status === 503) {
            this.phase = 'analyzing';
            this.phaseDetail = error.message;
            if (!(await sleepAbortable(1500, signal))) return;
            continue;
          }
          throw error;
        }
      }

      if (signal.aborted) return;
      await this.refreshSession(connClient, signal, rawTarget);
      if (signal.aborted) return;
      this.phase = 'ready';
      this.phaseDetail = null;

      void connClient.subscribeEvents(
        (frame) => this.handleSseFrame(frame, connClient, signal, rawTarget),
        (state, detail) => {
          if (signal.aborted) return;
          if (state === 'reconnecting') {
            this.needsReconnectRefresh = true;
          }
          this.sseState = state;
          if (state === 'auth_error' && detail) {
            this.actionError = detail;
          }
        },
        signal,
      );
    } catch (error) {
      if (signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) return;
      this.phase = 'error';
      this.phaseDetail = error instanceof Error ? error.message : 'Failed to connect to ghidraMCP.';
    }
  }
}

async function sleepAbortable(ms: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return false;
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(true), ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve(false);
      },
      { once: true },
    );
  });
}
