<script lang="ts">
  import Columns2Icon from '@lucide/svelte/icons/columns-2';
  import PlusIcon from '@lucide/svelte/icons/plus';
  import TerminalIcon from '@lucide/svelte/icons/terminal';
  import ServerBar from '#lib/components/ghidra/server-bar.svelte';
  import ServerWorkspace, { type WorkspaceSnapshot } from '#lib/components/ghidra/server-workspace.svelte';
  import { BackgroundPattern } from '#lib/components/ui/background-pattern/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { ThemePicker } from '#lib/components/ui/style/index.js';
  import {
    buildMultiServerQuery,
    buildNavUrl,
    buildServerQuery,
    formatServerTag,
    normalizeTarget,
    parseInitialTargets,
    parseNavState,
    removeSavedServer,
    SERVERS_STORAGE_KEY,
    TARGET_STORAGE_KEY,
    upsertSavedServer,
    type SavedServer,
    type UrlNavState,
  } from '#lib/ghidra-api.ts';
  import { onMount, untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';

  type PaneEntry = {
    id: string;
    slot: number;
    connectRequest: { raw: string; token?: string; preserveNav?: boolean; seq: number } | null;
    initialNav?: UrlNavState;
  };

  let nextPaneId = 0;
  let connectSeq = 0;

  let panes = $state<PaneEntry[]>([]);
  let activePaneId = $state('');
  let focusedPaneId = $state<string | null>(null);
  let savedServers = $state<SavedServer[]>([]);

  const snapshots = new SvelteMap<string, WorkspaceSnapshot>();
  const sessionTokens = new SvelteMap<string, string>();
  let urlSyncTimer: ReturnType<typeof setTimeout> | undefined;

  const paneSnapshots = $derived(
    panes.map((p) => ({
      pane: p,
      snap: snapshots.get(p.id),
    })),
  );

  const activeUrls = $derived(
    paneSnapshots
      .map((item) => item.snap?.baseUrl ?? '')
      .filter((url, idx, arr) => Boolean(url) && arr.indexOf(url) === idx),
  );

  const connectedSnapshots = $derived(
    paneSnapshots
      .map((item) => item.snap)
      .filter((s): s is WorkspaceSnapshot => Boolean(s && s.baseUrl && s.binaryName)),
  );

  const pageTitle = $derived.by(() => {
    if (connectedSnapshots.length === 1) {
      const s = connectedSnapshots[0];
      return `${s.binaryName} (${formatServerTag(s.baseUrl)}) · v${s.version} — Esperware`;
    }
    if (connectedSnapshots.length > 1) {
      const labels = connectedSnapshots.map((s) => `${s.binaryName} (${formatServerTag(s.baseUrl)})`).join(' | ');
      return `${connectedSnapshots.length} MCPs · ${labels} — Esperware`;
    }
    return 'Esperware Ghidra Viewer';
  });

  const activePaneLabel = $derived.by(() => {
    const idx = panes.findIndex((p) => p.id === activePaneId);
    const snap = snapshots.get(activePaneId);
    if (snap?.baseUrl) {
      return snap.binaryName ? `${snap.binaryName} (${formatServerTag(snap.baseUrl)})` : formatServerTag(snap.baseUrl);
    }
    return idx >= 0 ? `pane ${idx + 1}` : 'pane 1';
  });

  const showSplitGrid = $derived(panes.length > 1 && focusedPaneId === null);

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

  function findFreeSlot(): number {
    let slot = 0;
    while (panes.some((p) => p.slot === slot)) slot++;
    return slot;
  }

  function createPane(
    connect?: { raw: string; token?: string; preserveNav?: boolean },
    initialNav?: UrlNavState,
  ): PaneEntry {
    const idNum = nextPaneId++;
    const slot = findFreeSlot();
    return {
      id: `pane-${idNum}`,
      slot,
      connectRequest: connect ? { ...connect, seq: ++connectSeq } : null,
      initialNav,
    };
  }

  function resolveToken(raw: string, explicit?: string): string {
    if (explicit !== undefined) return explicit;
    try {
      return sessionTokens.get(normalizeTarget(raw)) ?? '';
    } catch {
      return '';
    }
  }

  function recordTokenAndServer(raw: string, token: string, label?: string) {
    try {
      const baseUrl = normalizeTarget(raw);
      if (token) {
        sessionTokens.set(baseUrl, token);
      }
      persistServers(upsertSavedServer(savedServers, { raw: raw.trim(), baseUrl, label }));
    } catch {
      // Target validation errors are handled inside the target pane/form.
    }
  }

  function connectInPane(paneId: string, raw: string, token?: string, preserveNav = false) {
    const nextToken = resolveToken(raw, token);
    recordTokenAndServer(raw, nextToken);
    panes = panes.map((p) =>
      p.id === paneId
        ? { ...p, connectRequest: { raw: raw.trim(), token: nextToken, preserveNav, seq: ++connectSeq } }
        : p,
    );
    activePaneId = paneId;
  }

  function addEmptyPane() {
    const entry = createPane();
    panes = [...panes, entry];
    activePaneId = entry.id;
    focusedPaneId = null;
  }

  function openInSplit(raw: string, token?: string, onInvalid?: (msg: string) => void) {
    const trimmed = raw.trim();
    try {
      normalizeTarget(trimmed);
    } catch (error) {
      onInvalid?.(error instanceof Error ? error.message : 'Invalid server port or URL.');
      return;
    }
    const nextToken = resolveToken(trimmed, token);
    recordTokenAndServer(trimmed, nextToken);
    const entry = createPane({ raw: trimmed, token: nextToken });
    panes = [...panes, entry];
    activePaneId = entry.id;
    focusedPaneId = null;
  }

  function closePane(paneId: string) {
    if (panes.length <= 1) return;
    const remaining = panes.filter((p) => p.id !== paneId);
    panes = remaining;
    snapshots.delete(paneId);
    if (focusedPaneId === paneId) focusedPaneId = null;
    if (activePaneId === paneId) activePaneId = remaining[0]?.id ?? '';
    scheduleUrlSync();
  }

  function toggleFocusPane(paneId: string) {
    focusedPaneId = focusedPaneId === paneId ? null : paneId;
    activePaneId = paneId;
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
      onInvalid?.(msg);
      return;
    }
    persistServers(upsertSavedServer(savedServers, { raw: trimmed, baseUrl: normalized }));
    window.open(query, '_blank', 'noopener');
  }

  function handleRemoveServer(baseUrl: string) {
    sessionTokens.delete(baseUrl);
    persistServers(removeSavedServer(savedServers, baseUrl));
  }

  function syncUrl() {
    if (urlSyncTimer) {
      clearTimeout(urlSyncTimer);
      urlSyncTimer = undefined;
    }
    if (typeof window === 'undefined') return;
    try {
      if (panes.length === 1) {
        const snap = snapshots.get(panes[0].id);
        if (!snap?.rawTarget) return;
        const nextSearch = buildNavUrl(snap.rawTarget, snap.navState);
        if (window.location.search !== nextSearch) {
          window.history.replaceState(null, '', nextSearch);
        }
        return;
      }

      const targets = panes
        .map((p) => snapshots.get(p.id)?.rawTarget?.trim() ?? '')
        .filter((raw) => {
          if (!raw) return false;
          try {
            normalizeTarget(raw);
            return true;
          } catch {
            return false;
          }
        });
      if (targets.length === 0) return;
      const nextSearch = buildMultiServerQuery(targets);
      if (nextSearch && window.location.search !== nextSearch) {
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

  function handleWorkspaceSnapshot(snap: WorkspaceSnapshot) {
    snapshots.set(snap.paneId, snap);
    scheduleUrlSync();
  }

  onMount(() => {
    savedServers = loadSavedServers();
    const initialTargets = parseInitialTargets(window.location.search);
    const params = new URLSearchParams(window.location.search);

    untrack(() => {
      if (initialTargets.length > 1) {
        const created = initialTargets.map((raw) => createPane({ raw }));
        panes = created;
        activePaneId = created[0].id;
      } else if (initialTargets.length === 1) {
        const nav = parseNavState(window.location.search);
        const p = createPane({ raw: initialTargets[0], preserveNav: true }, nav);
        panes = [p];
        activePaneId = p.id;
      } else if (!params.has('new') && savedServers.length > 0) {
        const nav = parseNavState(window.location.search);
        const p = createPane({ raw: savedServers[0].raw, preserveNav: true }, nav);
        panes = [p];
        activePaneId = p.id;
      } else {
        const p = createPane();
        panes = [p];
        activePaneId = p.id;
      }
    });

    const handleStorage = (event: StorageEvent) => {
      if (event.key === SERVERS_STORAGE_KEY) {
        savedServers = loadSavedServers();
      }
    };
    window.addEventListener('storage', handleStorage);

    return () => {
      window.removeEventListener('storage', handleStorage);
      if (urlSyncTimer) {
        clearTimeout(urlSyncTimer);
        urlSyncTimer = undefined;
      }
    };
  });
</script>

<svelte:head>
  <title>{pageTitle}</title>
</svelte:head>

<div class="flex min-h-screen flex-col">
  <section class="neoretro-border-b relative isolate overflow-hidden py-3">
    <BackgroundPattern pattern="grid" size={24} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      <Card.Root color="bright-black" class="py-3">
        <Card.Content class="flex flex-wrap items-center justify-between gap-3">
          <div class="flex min-w-0 flex-wrap items-center gap-2">
            <Badge color="cyan">
              <TerminalIcon />
              ESPERWARE
            </Badge>
            <h1 class="my-0 font-mono text-sm font-black tracking-tight">GHIDRA MCP DECK</h1>

            {#if panes.length > 1}
              <div class="flex flex-wrap items-center gap-1.5">
                <Button
                  color={focusedPaneId === null ? 'cyan' : 'white'}
                  size="sm"
                  aria-pressed={focusedPaneId === null}
                  onclick={() => (focusedPaneId = null)}
                >
                  <Columns2Icon />
                  Split ({panes.length})
                </Button>
                {#each paneSnapshots as item, idx (item.pane.id)}
                  {@const isShownFocused = focusedPaneId === item.pane.id}
                  {@const snap = item.snap}
                  {@const baseLabel = snap?.binaryName
                    ? `${snap.binaryName} (${formatServerTag(snap.baseUrl)})`
                    : snap?.baseUrl
                      ? formatServerTag(snap.baseUrl)
                      : `Pane ${idx + 1}`}
                  {@const suffix =
                    snap?.version !== null && snap?.version !== undefined
                      ? ` · v${snap.version}`
                      : snap &&
                          (snap.phase === 'error' || snap.phase === 'recovery_required' || snap.phase === 'analyzing')
                        ? ` · ${snap.statusBadgeText}`
                        : ''}
                  {@const pillColor =
                    snap && (snap.phase === 'error' || snap.phase === 'recovery_required')
                      ? 'red'
                      : isShownFocused
                        ? 'yellow'
                        : item.pane.id === activePaneId
                          ? 'blue'
                          : 'white'}
                  <Button
                    color={pillColor}
                    size="sm"
                    aria-pressed={isShownFocused}
                    onclick={() => toggleFocusPane(item.pane.id)}
                  >
                    {baseLabel}{suffix}
                  </Button>
                {/each}
              </div>
            {/if}
          </div>

          <div class="flex shrink-0 items-center gap-2">
            <Button color="magenta" size="sm" onclick={addEmptyPane}>
              <Columns2Icon />
              Add pane
            </Button>

            <Button color="green" size="sm" href="?new=1" target="_blank" rel="noopener">
              <PlusIcon />
              New tab
            </Button>

            <ThemePicker backgroundColor="yellow" />
          </div>
        </Card.Content>
      </Card.Root>
    </div>
  </section>

  <section class="relative isolate flex-1 overflow-hidden py-6">
    <BackgroundPattern pattern="cross" size={20} rotation={45} />
    <div class={showSplitGrid ? 'relative z-10 w-full px-4' : 'relative z-10 container mx-auto max-w-7xl px-4'}>
      <div class={showSplitGrid ? 'grid grid-cols-1 items-start gap-4 xl:grid-cols-2' : 'space-y-4'}>
        {#each panes as pane (pane.id)}
          <div
            class={focusedPaneId && focusedPaneId !== pane.id ? 'hidden' : 'min-w-0'}
            onfocusin={() => (activePaneId = pane.id)}
          >
            <ServerWorkspace
              paneId={pane.id}
              paneSlot={pane.slot}
              connectRequest={pane.connectRequest}
              initialNav={pane.initialNav}
              {savedServers}
              {activeUrls}
              canClose={panes.length > 1}
              isSplit={panes.length > 1}
              isFocused={focusedPaneId === pane.id}
              isActivePane={activePaneId === pane.id}
              onServerReady={(srv, tok) => {
                if (tok) sessionTokens.set(srv.baseUrl, tok);
                persistServers(upsertSavedServer(savedServers, srv));
              }}
              onConnectSaved={(srv) => connectInPane(pane.id, srv.raw)}
              onRemoveServer={handleRemoveServer}
              onOpenInNewTab={openInNewTab}
              onSplitServer={(raw, tok, onInvalid) => openInSplit(raw, tok, onInvalid)}
              onConnectAttempt={(raw, _normalized, tok) => recordTokenAndServer(raw, tok)}
              onClose={() => closePane(pane.id)}
              onToggleFocus={() => toggleFocusPane(pane.id)}
              onStateSnapshot={handleWorkspaceSnapshot}
            />
          </div>
        {/each}
      </div>
    </div>
  </section>

  <section class="neoretro-border-t relative isolate overflow-hidden py-3">
    <BackgroundPattern pattern="dots" size={16} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      <ServerBar
        {savedServers}
        {activeUrls}
        {activePaneLabel}
        onConnectInActive={(raw, tok) => {
          const targetId = activePaneId || panes[0]?.id;
          if (targetId) connectInPane(targetId, raw, tok);
        }}
        onOpenInSplit={(raw, tok) => openInSplit(raw, tok)}
        onOpenInNewTab={openInNewTab}
        onRemoveServer={handleRemoveServer}
      />
    </div>
  </section>
</div>
