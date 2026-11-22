<script lang="ts">
  import CompassIcon from '@lucide/svelte/icons/compass';
  import CpuIcon from '@lucide/svelte/icons/cpu';
  import DownloadIcon from '@lucide/svelte/icons/download';
  import ExternalLinkIcon from '@lucide/svelte/icons/external-link';
  import HistoryIcon from '@lucide/svelte/icons/history';
  import PlugIcon from '@lucide/svelte/icons/plug';
  import PlusIcon from '@lucide/svelte/icons/plus';
  import PowerIcon from '@lucide/svelte/icons/power';
  import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
  import SearchCodeIcon from '@lucide/svelte/icons/search-code';
  import ServerIcon from '@lucide/svelte/icons/server';
  import ShieldAlertIcon from '@lucide/svelte/icons/shield-alert';
  import TerminalIcon from '@lucide/svelte/icons/terminal';
  import Trash2Icon from '@lucide/svelte/icons/trash-2';
  import XIcon from '@lucide/svelte/icons/x';
  import ConfirmDialog from '#lib/components/confirm-dialog.svelte';
  import CopyButton from '#lib/components/copy-button.svelte';
  import BinaryOverview from '#lib/components/ghidra/binary-overview.svelte';
  import ExplorePanel from '#lib/components/ghidra/explore-panel.svelte';
  import FunctionInspector from '#lib/components/ghidra/function-inspector.svelte';
  import VersionScrubber from '#lib/components/ghidra/version-scrubber.svelte';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { BackgroundPattern } from '#lib/components/ui/background-pattern/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Collapsible from '#lib/components/ui/collapsible/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import { ThemePicker } from '#lib/components/ui/style/index.js';
  import * as Tabs from '#lib/components/ui/tabs/index.js';
  import {
    ApiRequestError,
    buildNavUrl,
    buildServerQuery,
    collectTouchedFunctions,
    createGhidraClient,
    formatServerTag,
    normalizeTarget,
    parseNavState,
    removeSavedServer,
    SERVERS_STORAGE_KEY,
    TARGET_STORAGE_KEY,
    upsertSavedServer,
    type ExportResponse,
    type GhidraClient,
    type SavedServer,
    type SseConnectionState,
    type SseFrame,
    type StatusResponse,
    type UrlNavState,
    type VersionDetail,
    type VersionSummary,
    type WorkspaceTab,
  } from '#lib/ghidra-api.ts';
  import { onMount, untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';

  type Phase = 'disconnected' | 'connecting' | 'analyzing' | 'ready' | 'error' | 'recovery_required' | 'stopped';

  let targetInput = $state('');
  let tokenInput = $state('');
  let footerTarget = $state('');
  let footerToken = $state('');
  let footerError = $state<string | null>(null);
  let switcherOpen = $state(false);
  let savedServers = $state<SavedServer[]>([]);

  let connectedRawTarget = $state('');
  let activeTab = $state<WorkspaceTab>('scrubber');
  let navState = $state<UrlNavState>({ tab: 'scrubber' });
  let client = $state<GhidraClient | null>(null);
  let phase = $state<Phase>('disconnected');
  let phaseDetail = $state<string | null>(null);
  let status = $state<StatusResponse | null>(null);
  let versions = $state<VersionSummary[]>([]);
  let versionCache = new SvelteMap<number, VersionDetail>();

  let sseState = $state<SseConnectionState>('disconnected');
  let lastEvent = $state<{ event: string; at: string } | null>(null);

  let actionError = $state<string | null>(null);
  let exportNotice = $state<ExportResponse | null>(null);
  let exportLoading = $state(false);
  let shutdownLoading = $state(false);

  let focusScrubReq = $state<{ addr: string; seq: number } | null>(null);
  let focusInspectReq = $state<{ target: string; seq: number } | null>(null);
  let focusMemoryReq = $state<{ addr: string; size?: number; seq: number } | null>(null);
  let lastVersionEvent = $state<{ version: number; operation: string; addresses: string[] } | null>(null);
  let navSeq = 0;

  let activeConnection: AbortController | null = null;
  let urlSyncTimer: ReturnType<typeof setTimeout> | undefined;
  let inFlightVersions = new SvelteMap<number, Promise<VersionDetail | null>>();

  const touchedAddresses = $derived(new Set(collectTouchedFunctions(versions).map((fn) => fn.address.toLowerCase())));

  const statusBadgeColor = $derived.by(() => {
    if (phase === 'ready' && sseState === 'connected') return 'green';
    if (phase === 'ready' || phase === 'analyzing' || phase === 'connecting') return 'yellow';
    if (phase === 'error' || phase === 'recovery_required') return 'red';
    return 'bright-black';
  });

  const statusBadgeText = $derived.by(() => {
    if (phase === 'ready') {
      if (sseState === 'connected') return 'LIVE SSE';
      if (sseState === 'reconnecting') return 'RECONNECTING';
      if (sseState === 'auth_error') return 'AUTH ERROR';
      return 'READY';
    }
    if (phase === 'analyzing') return 'ANALYZING';
    if (phase === 'connecting') return 'CONNECTING';
    if (phase === 'recovery_required') return 'RECOVERY REQUIRED';
    if (phase === 'stopped') return 'STOPPED';
    if (phase === 'error') return 'UNREACHABLE';
    return 'DISCONNECTED';
  });

  function loadSavedServers(): SavedServer[] {
    try {
      const rawJson = localStorage.getItem(SERVERS_STORAGE_KEY);
      if (rawJson) {
        const parsed = JSON.parse(rawJson) as unknown;
        if (Array.isArray(parsed)) {
          return parsed.filter(
            (item): item is SavedServer =>
              Boolean(item) &&
              typeof item === 'object' &&
              typeof (item as SavedServer).raw === 'string' &&
              typeof (item as SavedServer).baseUrl === 'string',
          );
        }
      }
      const legacy = localStorage.getItem(TARGET_STORAGE_KEY);
      if (legacy) {
        return [{ raw: legacy, baseUrl: normalizeTarget(legacy) }];
      }
    } catch {
      // Ignore storage or legacy target parse errors.
    }
    return [];
  }

  function persistServers(next: SavedServer[]) {
    savedServers = next;
    try {
      localStorage.setItem(SERVERS_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage access restrictions.
    }
  }

  async function ensureVersionDetail(version: number): Promise<VersionDetail | null> {
    const cached = versionCache.get(version);
    if (cached) return cached;
    if (!client) return null;

    const existing = inFlightVersions.get(version);
    if (existing) return existing;

    const signal = activeConnection?.signal;
    const promise = client
      .version(version, signal)
      .then((res) => {
        versionCache.set(version, res.version);
        return res.version;
      })
      .catch((error) => {
        if (error instanceof DOMException && error.name === 'AbortError') return null;
        throw error;
      })
      .finally(() => {
        inFlightVersions.delete(version);
      });

    inFlightVersions.set(version, promise);
    return promise;
  }

  async function refreshSession(connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    const prevStatus = status;
    const [nextStatus, nextVersions] = await Promise.all([connClient.status(signal), connClient.versions(signal)]);
    if (signal.aborted) return;
    if (
      prevStatus &&
      (nextStatus.binary_sha256 !== prevStatus.binary_sha256 || nextStatus.version < prevStatus.version)
    ) {
      versionCache.clear();
      inFlightVersions.clear();
    }
    status = nextStatus;
    versions = nextVersions.versions;
    persistServers(
      upsertSavedServer(savedServers, {
        raw: rawTarget,
        baseUrl: connClient.baseUrl,
        label: nextStatus.binary_name,
      }),
    );
  }

  function handleSseFrame(frame: SseFrame, connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    lastEvent = { event: frame.event, at: new Date().toLocaleTimeString() };
    if (frame.event === 'checkpoint_saved') {
      const ver = Number(frame.data.version);
      if (Number.isFinite(ver)) versionCache.delete(ver);
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
        lastVersionEvent = { version: ver, operation, addresses };
      }
    }
    if (frame.event === 'status') {
      const sseVer = Number(frame.data.version);
      if (phase === 'ready' && status && Number.isFinite(sseVer) && sseVer === status.version) {
        return;
      }
    }
    if (frame.event === 'status' || frame.event === 'version_created' || frame.event === 'checkpoint_saved') {
      void refreshSession(connClient, signal, rawTarget).catch((error) => {
        if (!(error instanceof DOMException && error.name === 'AbortError')) {
          actionError = error instanceof Error ? error.message : 'Failed to refresh after SSE update.';
        }
      });
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

  async function bootConnection(connClient: GhidraClient, signal: AbortSignal, rawTarget: string) {
    try {
      while (!signal.aborted) {
        try {
          const health = await connClient.health(signal);
          if (signal.aborted) return;
          if (health.status === 'analyzing') {
            phase = 'analyzing';
            phaseDetail = 'Ghidra is importing and analyzing the binary...';
            const keepWaiting = await sleepAbortable(1500, signal);
            if (!keepWaiting) return;
            continue;
          }
          if (health.status === 'recovery_required') {
            phase = 'recovery_required';
            phaseDetail = health.error || 'Restart the ghidraMCP server to recover the workspace.';
            return;
          }
          if (health.status === 'error' || !health.ok) {
            phase = 'error';
            phaseDetail = health.error || `Server reported status: ${health.status}`;
            return;
          }
          break;
        } catch (error) {
          if (signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) return;
          if (error instanceof ApiRequestError && error.status === 503) {
            phase = 'analyzing';
            phaseDetail = error.message;
            const keepWaiting = await sleepAbortable(1500, signal);
            if (!keepWaiting) return;
            continue;
          }
          throw error;
        }
      }

      if (signal.aborted) return;
      await refreshSession(connClient, signal, rawTarget);
      if (signal.aborted) return;
      phase = 'ready';
      phaseDetail = null;

      void connClient.subscribeEvents(
        (frame) => handleSseFrame(frame, connClient, signal, rawTarget),
        (state, detail) => {
          if (signal.aborted) return;
          sseState = state;
          if (state === 'auth_error' && detail) {
            actionError = detail;
          }
        },
        signal,
      );
    } catch (error) {
      if (signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) return;
      phase = 'error';
      phaseDetail = error instanceof Error ? error.message : 'Failed to connect to ghidraMCP.';
    }
  }

  function syncUrl() {
    if (urlSyncTimer) {
      clearTimeout(urlSyncTimer);
      urlSyncTimer = undefined;
    }
    if (!connectedRawTarget || typeof window === 'undefined') return;
    try {
      const nextSearch = buildNavUrl(connectedRawTarget, navState);
      if (window.location.search !== nextSearch) {
        window.history.replaceState(null, '', nextSearch);
      }
    } catch {
      // Ignore invalid intermediate target inputs.
    }
  }

  function scheduleUrlSync() {
    if (urlSyncTimer) clearTimeout(urlSyncTimer);
    urlSyncTimer = setTimeout(() => {
      syncUrl();
    }, 150);
  }

  function handleNavPatch(patch: Partial<UrlNavState>) {
    navState = { ...navState, ...patch };
    scheduleUrlSync();
  }

  function connectTarget(rawOverride?: string, tokenOverride?: string, preserveNav = false) {
    activeConnection?.abort();
    inFlightVersions.clear();
    versionCache.clear();
    actionError = null;
    exportNotice = null;
    exportLoading = false;
    shutdownLoading = false;
    lastVersionEvent = null;
    footerError = null;
    status = null;
    versions = [];
    lastEvent = null;
    sseState = 'disconnected';

    const raw = (rawOverride ?? targetInput).trim();
    const token = tokenOverride ?? tokenInput;
    targetInput = raw;
    tokenInput = token;

    let normalized: string;
    try {
      normalized = normalizeTarget(raw);
    } catch (error) {
      phase = 'error';
      phaseDetail = error instanceof Error ? error.message : 'Invalid target.';
      return;
    }

    if (!preserveNav) {
      activeTab = 'scrubber';
      navState = { tab: 'scrubber' };
    }
    connectedRawTarget = raw;
    switcherOpen = false;
    persistServers(upsertSavedServer(savedServers, { raw, baseUrl: normalized }));
    syncUrl();

    const controller = new AbortController();
    activeConnection = controller;
    const nextClient = createGhidraClient(normalized, token);
    client = nextClient;
    phase = 'connecting';
    phaseDetail = `Connecting to ${normalized}...`;

    void bootConnection(nextClient, controller.signal, raw);
  }

  function connectSavedServer(srv: SavedServer) {
    const nextToken = client?.baseUrl === srv.baseUrl ? tokenInput : '';
    connectTarget(srv.raw, nextToken);
  }

  function connectFromFooter() {
    footerError = null;
    const raw = footerTarget.trim();
    try {
      normalizeTarget(raw);
    } catch (error) {
      footerError = error instanceof Error ? error.message : 'Invalid server port or URL.';
      return;
    }
    connectTarget(raw, footerToken);
  }

  function openInNewTab(raw: string, onInvalid?: (msg: string) => void) {
    const trimmed = raw.trim();
    let normalized: string;
    let query: string;
    try {
      normalized = normalizeTarget(trimmed);
      query = buildServerQuery(trimmed);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Invalid server port or URL.';
      if (onInvalid) {
        onInvalid(msg);
      } else {
        phase = 'error';
        phaseDetail = msg;
      }
      return;
    }
    persistServers(upsertSavedServer(savedServers, { raw: trimmed, baseUrl: normalized }));
    window.open(query, '_blank', 'noopener');
  }

  function handleRemoveServer(baseUrl: string) {
    persistServers(removeSavedServer(savedServers, baseUrl));
  }

  async function handleExport() {
    if (!client) return;
    exportLoading = true;
    actionError = null;
    exportNotice = null;
    try {
      exportNotice = await client.exportSnapshot(activeConnection?.signal);
    } catch (error) {
      actionError =
        error instanceof ApiRequestError && error.status === 401
          ? 'Export requires a valid write (--rw-token) token.'
          : error instanceof Error
            ? error.message
            : 'Export failed.';
    } finally {
      exportLoading = false;
    }
  }

  async function handleShutdown() {
    if (!client) return;
    shutdownLoading = true;
    actionError = null;
    try {
      await client.shutdown(activeConnection?.signal);
      activeConnection?.abort();
      sseState = 'disconnected';
      phase = 'stopped';
      phaseDetail = 'Server shutdown initiated cleanly.';
    } catch (error) {
      actionError =
        error instanceof ApiRequestError && error.status === 401
          ? 'Shutdown requires a valid write (--rw-token) token.'
          : error instanceof Error
            ? error.message
            : 'Shutdown failed.';
    } finally {
      shutdownLoading = false;
    }
  }

  function jumpToFunction(target: string) {
    focusInspectReq = { target, seq: ++navSeq };
    activeTab = 'functions';
  }

  function jumpToScrubber(addr: string) {
    focusScrubReq = { addr, seq: ++navSeq };
    activeTab = 'scrubber';
  }

  function jumpToMemory(addr: string, size?: number) {
    focusMemoryReq = { addr, size, seq: ++navSeq };
    activeTab = 'explore';
  }

  $effect(() => {
    const tab = activeTab;
    untrack(() => {
      if (navState.tab !== tab) {
        navState = { ...navState, tab };
      }
      syncUrl();
    });
  });

  onMount(() => {
    const params = new URLSearchParams(window.location.search);
    savedServers = loadSavedServers();

    if (!params.has('new')) {
      const parsedNav = parseNavState(window.location.search);
      activeTab = parsedNav.tab;
      navState = parsedNav;

      const initial = params.get('port') || params.get('api') || savedServers[0]?.raw || '';
      if (initial) {
        targetInput = initial;
        connectTarget(initial, tokenInput, true);
      }
    }

    return () => {
      if (urlSyncTimer) {
        clearTimeout(urlSyncTimer);
        urlSyncTimer = undefined;
      }
      activeConnection?.abort();
    };
  });
</script>

<svelte:head>
  <title>
    {status && client
      ? `${status.binary_name} (${formatServerTag(client.baseUrl)}) · v${status.version} — Esperware`
      : 'Esperware Ghidra Viewer'}
  </title>
</svelte:head>

<div class="flex min-h-screen flex-col">
  <section class="neoretro-border-b relative isolate overflow-hidden py-3">
    <BackgroundPattern pattern="grid" size={24} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      <Card.Root color="bright-black" class="py-3">
        <Card.Content class="space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex min-w-0 items-center gap-2">
              <Badge color="cyan">
                <TerminalIcon />
                ESPERWARE
              </Badge>
              <Badge color={statusBadgeColor}>{statusBadgeText}</Badge>
              {#if status}
                <span class="min-w-0 truncate font-mono text-sm font-black">{status.binary_name}</span>
                <Badge color="yellow">v{status.version}</Badge>
              {/if}
            </div>

            <div class="flex shrink-0 items-center gap-2">
              {#if status}
                <Button color="cyan" size="sm" disabled={exportLoading || phase !== 'ready'} onclick={handleExport}>
                  {#if exportLoading}
                    <Spinner />
                  {:else}
                    <DownloadIcon />
                  {/if}
                  Export
                </Button>

                <ConfirmDialog
                  title="Shut down ghidraMCP?"
                  description="Gracefully stops the headless Ghidra server on this port. Committed versions stay persisted in the work directory."
                  confirmText="Shutdown"
                  color="yellow"
                  actionColor="red"
                  cancelColor="white"
                  onConfirm={() => void handleShutdown()}
                >
                  {#snippet children({ props })}
                    <Button
                      {...props}
                      tabindex={0}
                      color="red"
                      size="sm"
                      disabled={shutdownLoading || phase !== 'ready'}
                    >
                      <PowerIcon />
                      Shutdown
                    </Button>
                  {/snippet}
                </ConfirmDialog>

                <Button color="green" size="sm" href="?new=1" target="_blank" rel="noopener">
                  <PlusIcon />
                  New tab
                </Button>
              {/if}

              <ThemePicker backgroundColor="yellow" />
            </div>
          </div>

          {#if actionError}
            <Alert.Root color="red">
              <ShieldAlertIcon />
              <Alert.Title>Request error</Alert.Title>
              <Alert.Description>{actionError}</Alert.Description>
            </Alert.Root>
          {/if}

          {#if exportNotice}
            <Alert.Root color="green">
              <DownloadIcon />
              <Alert.Title>Snapshot exported to {exportNotice.dir} (v{exportNotice.version})</Alert.Title>
              <Alert.Description class="font-mono text-xs">
                {exportNotice.files.length} files · {exportNotice.counts.functions ?? 0} functions ·
                {exportNotice.counts.source_files ?? 0} source files · {exportNotice.counts.edges ?? 0} edges
              </Alert.Description>
            </Alert.Root>
          {/if}
        </Card.Content>
      </Card.Root>
    </div>
  </section>

  <section class="relative isolate flex-1 overflow-hidden py-6">
    <BackgroundPattern pattern="cross" size={20} rotation={45} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      {#if phase === 'ready' && client && status}
        {#key client.baseUrl}
          <Tabs.Root bind:value={activeTab} activeColor="cyan" inactiveColor="white" class="space-y-4">
            <Tabs.List>
              <Tabs.Trigger value="scrubber">
                <HistoryIcon />
                Scrubber
              </Tabs.Trigger>
              <Tabs.Trigger value="functions">
                <SearchCodeIcon />
                Functions
              </Tabs.Trigger>
              <Tabs.Trigger value="explore">
                <CompassIcon />
                Explore
              </Tabs.Trigger>
              <Tabs.Trigger value="binary">
                <CpuIcon />
                Binary
              </Tabs.Trigger>
            </Tabs.List>

            <Tabs.Content value="scrubber">
              <VersionScrubber
                {client}
                {versions}
                currentVersion={status.version}
                segments={status.segments}
                active={activeTab === 'scrubber'}
                {versionCache}
                {ensureVersionDetail}
                focusRequest={focusScrubReq}
                initialNav={navState}
                onInspectFunction={jumpToFunction}
                onNavChange={handleNavPatch}
              />
            </Tabs.Content>

            <Tabs.Content value="functions">
              <FunctionInspector
                {client}
                currentVersion={status.version}
                segments={status.segments}
                active={activeTab === 'functions'}
                {touchedAddresses}
                {lastVersionEvent}
                inspectRequest={focusInspectReq}
                initialNav={navState}
                onScrubFunction={jumpToScrubber}
                onOpenMemory={jumpToMemory}
                onNavChange={handleNavPatch}
              />
            </Tabs.Content>

            <Tabs.Content value="explore">
              <ExplorePanel
                {client}
                currentVersion={status.version}
                segments={status.segments}
                active={activeTab === 'explore'}
                memoryRequest={focusMemoryReq}
                initialNav={navState}
                onInspectFunction={jumpToFunction}
                onNavChange={handleNavPatch}
              />
            </Tabs.Content>

            <Tabs.Content value="binary">
              <BinaryOverview {status} onInspectFunction={jumpToFunction} onOpenMemory={jumpToMemory} />
            </Tabs.Content>
          </Tabs.Root>
        {/key}
      {:else}
        <div class="mx-auto max-w-2xl py-4">
          <Card.Root color="bright-black">
            <Card.Header>
              <Card.Title class="flex items-center gap-2">
                {#if phase === 'connecting' || phase === 'analyzing'}
                  <Spinner color="yellow" />
                {/if}
                <span>
                  {#if phase === 'disconnected'}
                    Tap into headless Ghidra
                  {:else if phase === 'connecting'}
                    Connecting to server...
                  {:else if phase === 'analyzing'}
                    Analyzing binary in Ghidra...
                  {:else if phase === 'recovery_required'}
                    Workspace recovery required
                  {:else if phase === 'stopped'}
                    Server stopped
                  {:else}
                    Connection failed
                  {/if}
                </span>
              </Card.Title>
              <Card.Description>
                Enter the port printed by `just run` (or an HTTP URL). Open another browser tab anytime to inspect
                multiple binaries side-by-side.
              </Card.Description>
            </Card.Header>

            <Card.Content class="space-y-4">
              {#if phase === 'error' || phase === 'recovery_required'}
                <Alert.Root color="red">
                  <ShieldAlertIcon />
                  <Alert.Title
                    >{phase === 'recovery_required' ? 'Workspace recovery required' : 'Connection error'}</Alert.Title
                  >
                  <Alert.Description>{phaseDetail}</Alert.Description>
                </Alert.Root>
              {:else if phase === 'stopped' || (phaseDetail && (phase === 'connecting' || phase === 'analyzing'))}
                <Alert.Root color={phase === 'stopped' ? 'yellow' : 'cyan'}>
                  <Alert.Title>{phase === 'stopped' ? 'Stopped' : 'Status'}</Alert.Title>
                  <Alert.Description>{phaseDetail}</Alert.Description>
                </Alert.Root>
              {/if}

              <form
                class="space-y-3"
                onsubmit={(e) => {
                  e.preventDefault();
                  connectTarget();
                }}
              >
                <Field.Field>
                  <Field.Label for="target-input">Server Port or URL</Field.Label>
                  <Input
                    id="target-input"
                    color="white"
                    bind:value={targetInput}
                    placeholder="43299 or http://127.0.0.1:8765"
                  />
                </Field.Field>

                <Field.Field>
                  <Field.Label for="token-input">Bearer Token (optional)</Field.Label>
                  <Input
                    id="token-input"
                    color="white"
                    type="password"
                    autocomplete="off"
                    bind:value={tokenInput}
                    placeholder="RO or RW token"
                  />
                </Field.Field>

                <div class="flex flex-wrap items-center gap-2">
                  <Button type="submit" color="green">
                    <PlugIcon />
                    Connect
                  </Button>
                  <Button
                    type="button"
                    color="blue"
                    onclick={() =>
                      openInNewTab(targetInput, (msg) => {
                        phase = 'error';
                        phaseDetail = msg;
                      })}
                  >
                    <ExternalLinkIcon />
                    Open in new tab
                  </Button>
                  {#if phase === 'error' || phase === 'stopped'}
                    <Button type="button" color="yellow" onclick={() => connectTarget(undefined, undefined, true)}>
                      <RefreshCwIcon />
                      Retry
                    </Button>
                  {/if}
                </div>
              </form>

              {#if savedServers.length > 0}
                <div class="space-y-2 pt-2">
                  <div class="font-mono text-xs font-bold">Saved servers ({savedServers.length})</div>
                  {#each savedServers as srv (srv.baseUrl)}
                    <Item.Root color="white" size="sm" class="mb-0">
                      <Item.Content>
                        <Item.Title class="font-mono">{srv.label || formatServerTag(srv.baseUrl)}</Item.Title>
                        <Item.Description class="font-mono text-xs">{srv.baseUrl}</Item.Description>
                      </Item.Content>
                      <Item.Actions>
                        <Button color="cyan" size="sm" onclick={() => connectSavedServer(srv)}>Connect</Button>
                        <Button
                          color="blue"
                          size="sm"
                          href={buildServerQuery(srv.raw)}
                          target="_blank"
                          rel="noopener"
                          aria-label={`Open ${srv.baseUrl} in new tab`}
                        >
                          <ExternalLinkIcon />
                          Tab
                        </Button>
                        <Button
                          color="red"
                          size="icon-sm"
                          aria-label={`Remove ${srv.baseUrl}`}
                          onclick={() => handleRemoveServer(srv.baseUrl)}
                        >
                          <Trash2Icon />
                        </Button>
                      </Item.Actions>
                    </Item.Root>
                  {/each}
                </div>
              {/if}
            </Card.Content>
          </Card.Root>
        </div>
      {/if}
    </div>
  </section>

  <section class="neoretro-border-t relative isolate overflow-hidden py-3">
    <BackgroundPattern pattern="dots" size={16} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      <Card.Root color="bright-black" class="py-3">
        <Card.Content class="space-y-3">
          <Collapsible.Root bind:open={switcherOpen}>
            <div class="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
              <div class="flex flex-wrap items-center gap-2">
                <Badge color="white">{client ? formatServerTag(client.baseUrl) : 'no server'}</Badge>
                <span>SSE: {sseState}</span>
                {#if lastEvent}
                  <span>·</span>
                  <span>last: {lastEvent.event} @ {lastEvent.at}</span>
                {/if}
                {#if status}
                  <span>·</span>
                  <span>sha256:{status.binary_sha256.slice(0, 12)}</span>
                {/if}
              </div>

              <div class="flex flex-wrap items-center gap-2">
                {#if status}
                  <div class="flex items-center gap-1">
                    <Badge color="white">RO</Badge>
                    <CopyButton
                      value={status.mcp_ro_url}
                      variant="icon"
                      color="cyan"
                      size="sm"
                      aria-label="Copy read-only MCP URL"
                    />
                  </div>
                  <div class="flex items-center gap-1">
                    <Badge color="white">RW</Badge>
                    <CopyButton
                      value={status.mcp_rw_url}
                      variant="icon"
                      color="magenta"
                      size="sm"
                      aria-label="Copy read-write MCP URL"
                    />
                  </div>
                {/if}

                <Collapsible.Trigger>
                  {#snippet child({ props })}
                    <Button {...props} tabindex={0} color="yellow" size="sm">
                      <ServerIcon />
                      Switch / Add server
                    </Button>
                  {/snippet}
                </Collapsible.Trigger>
              </div>
            </div>

            {#if savedServers.length > 1}
              <div class="flex flex-wrap items-center gap-2 pt-3">
                {#each savedServers as srv (srv.baseUrl)}
                  {@const isCurrent = client?.baseUrl === srv.baseUrl}
                  <ButtonGroup.Root>
                    <Button color={isCurrent ? 'cyan' : 'white'} size="sm" onclick={() => connectSavedServer(srv)}>
                      {srv.label ? `${srv.label} (${formatServerTag(srv.baseUrl)})` : formatServerTag(srv.baseUrl)}
                    </Button>
                    <Button
                      color="blue"
                      size="icon-sm"
                      href={buildServerQuery(srv.raw)}
                      target="_blank"
                      rel="noopener"
                      aria-label={`Open ${srv.baseUrl} in new tab`}
                    >
                      <ExternalLinkIcon />
                    </Button>
                    <Button
                      color="red"
                      size="icon-sm"
                      aria-label={`Remove ${srv.baseUrl}`}
                      onclick={() => handleRemoveServer(srv.baseUrl)}
                    >
                      <XIcon />
                    </Button>
                  </ButtonGroup.Root>
                {/each}
              </div>
            {/if}

            <Collapsible.Content class="pt-3">
              <form
                class="grid grid-cols-1 gap-3 md:grid-cols-[1fr_220px_auto_auto] md:items-end"
                onsubmit={(e) => {
                  e.preventDefault();
                  connectFromFooter();
                }}
              >
                <Field.Field>
                  <Field.Label for="footer-target">Server Port or URL</Field.Label>
                  <Input
                    id="footer-target"
                    color="white"
                    bind:value={footerTarget}
                    placeholder="43299 or http://127.0.0.1:8765"
                  />
                </Field.Field>

                <Field.Field>
                  <Field.Label for="footer-token">Bearer Token (optional)</Field.Label>
                  <Input
                    id="footer-token"
                    color="white"
                    type="password"
                    autocomplete="off"
                    bind:value={footerToken}
                    placeholder="RO or RW token"
                  />
                </Field.Field>

                <Button type="submit" color="green" size="sm">
                  <PlugIcon />
                  Connect here
                </Button>

                <Button
                  type="button"
                  color="blue"
                  size="sm"
                  onclick={() =>
                    openInNewTab(footerTarget, (msg) => {
                      footerError = msg;
                    })}
                >
                  <ExternalLinkIcon />
                  Open in new tab
                </Button>
              </form>

              {#if footerError}
                <Alert.Root color="red" class="mt-3">
                  <ShieldAlertIcon />
                  <Alert.Title>Invalid server</Alert.Title>
                  <Alert.Description>{footerError}</Alert.Description>
                </Alert.Root>
              {/if}
            </Collapsible.Content>
          </Collapsible.Root>
        </Card.Content>
      </Card.Root>
    </div>
  </section>
</div>
