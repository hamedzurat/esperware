<script lang="ts">
  import Columns2Icon from '@lucide/svelte/icons/columns-2';
  import CompassIcon from '@lucide/svelte/icons/compass';
  import CpuIcon from '@lucide/svelte/icons/cpu';
  import DownloadIcon from '@lucide/svelte/icons/download';
  import ExternalLinkIcon from '@lucide/svelte/icons/external-link';
  import HistoryIcon from '@lucide/svelte/icons/history';
  import Maximize2Icon from '@lucide/svelte/icons/maximize-2';
  import Minimize2Icon from '@lucide/svelte/icons/minimize-2';
  import PowerIcon from '@lucide/svelte/icons/power';
  import SearchCodeIcon from '@lucide/svelte/icons/search-code';
  import ShieldAlertIcon from '@lucide/svelte/icons/shield-alert';
  import Trash2Icon from '@lucide/svelte/icons/trash-2';
  import XIcon from '@lucide/svelte/icons/x';
  import ConfirmDialog from '#lib/components/confirm-dialog.svelte';
  import CopyButton from '#lib/components/copy-button.svelte';
  import BinaryOverview from '#lib/components/ghidra/binary-overview.svelte';
  import ExplorePanel from '#lib/components/ghidra/explore-panel.svelte';
  import FunctionInspector from '#lib/components/ghidra/function-inspector.svelte';
  import ServerConnectForm from '#lib/components/ghidra/server-connect-form.svelte';
  import VersionScrubber from '#lib/components/ghidra/version-scrubber.svelte';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Tabs from '#lib/components/ui/tabs/index.js';
  import {
    buildServerQuery,
    formatServerTag,
    type SavedServer,
    type UrlNavState,
    type WorkspaceTab,
  } from '#lib/ghidra-api.ts';
  import { GhidraSession, type SessionPhase } from '#lib/ghidra-session.svelte.ts';
  import { untrack } from 'svelte';

  export type WorkspaceSnapshot = {
    paneId: string;
    rawTarget: string;
    baseUrl: string;
    binaryName: string | null;
    version: number | null;
    phase: SessionPhase;
    statusBadgeColor: 'green' | 'yellow' | 'red' | 'white';
    statusBadgeText: string;
    navState: UrlNavState;
  };

  let {
    paneId,
    paneSlot,
    connectRequest = null,
    initialNav = undefined,
    savedServers = [],
    activeUrls = [],
    canClose = false,
    isSplit = false,
    isFocused = false,
    isActivePane = false,
    onServerReady,
    onConnectSaved,
    onRemoveServer,
    onOpenInNewTab,
    onSplitServer,
    onConnectAttempt = undefined,
    onClose,
    onToggleFocus,
    onStateSnapshot,
  }: {
    paneId: string;
    paneSlot: number;
    connectRequest?: { raw: string; token?: string; preserveNav?: boolean; seq: number } | null;
    initialNav?: UrlNavState;
    savedServers?: SavedServer[];
    activeUrls?: string[];
    canClose?: boolean;
    isSplit?: boolean;
    isFocused?: boolean;
    isActivePane?: boolean;
    onServerReady: (server: SavedServer, token: string) => void;
    onConnectSaved: (srv: SavedServer) => void;
    onRemoveServer: (baseUrl: string) => void;
    onOpenInNewTab: (raw: string, onInvalid?: (msg: string) => void) => void;
    onSplitServer: (raw: string, token?: string, onInvalid?: (msg: string) => void) => void;
    onConnectAttempt?: (raw: string, normalized: string, token: string) => void;
    onClose: () => void;
    onToggleFocus: () => void;
    onStateSnapshot: (snap: WorkspaceSnapshot) => void;
  } = $props();

  const session = new GhidraSession({
    onServerReady: (srv) => onServerReady(srv, session.token),
  });

  let targetInput = $state('');
  let tokenInput = $state('');
  let localFormError = $state<string | null>(null);
  let activeTab = $state<WorkspaceTab>(untrack(() => initialNav?.tab ?? 'scrubber'));
  let navState = $state<UrlNavState>(untrack(() => initialNav ?? { tab: 'scrubber' }));

  let focusScrubReq = $state<{ addr: string; seq: number } | null>(null);
  let focusInspectReq = $state<{ target: string; seq: number } | null>(null);
  let focusMemoryReq = $state<{ addr: string; size?: number; seq: number } | null>(null);
  let navSeq = 0;
  let lastConnectSeq = 0;

  function connectTarget(rawOverride?: string, tokenOverride?: string, preserveNav = false) {
    localFormError = null;
    const raw = (rawOverride ?? targetInput).trim();
    const token = tokenOverride ?? tokenInput;
    targetInput = raw;
    tokenInput = token;

    if (!preserveNav) {
      activeTab = 'scrubber';
      navState = { tab: 'scrubber' };
    }
    const normalized = session.connect(raw, token);
    if (normalized) {
      onConnectAttempt?.(raw, normalized, token);
    }
  }

  function handleNavPatch(patch: Partial<UrlNavState>) {
    navState = { ...navState, ...patch };
  }

  function jumpToFunction(target: string) {
    focusInspectReq = { target, seq: ++navSeq };
    navState = { ...navState, tab: 'functions', fnTarget: target, fnView: 'pseudocode' };
    activeTab = 'functions';
  }

  function jumpToScrubber(addr: string) {
    focusScrubReq = { addr, seq: ++navSeq };
    navState = { ...navState, tab: 'scrubber', scrubMode: 'snapshot', scrubFn: addr };
    activeTab = 'scrubber';
  }

  function jumpToMemory(addr: string, size?: number) {
    focusMemoryReq = { addr, size, seq: ++navSeq };
    navState = {
      ...navState,
      tab: 'explore',
      exploreSub: 'memory',
      memAddr: addr,
      memSize: size ?? navState.memSize,
    };
    activeTab = 'explore';
  }

  $effect(() => {
    const req = connectRequest;
    if (!req || req.seq === lastConnectSeq) return;
    lastConnectSeq = req.seq;
    untrack(() => {
      connectTarget(req.raw, req.token ?? '', Boolean(req.preserveNav));
    });
  });

  $effect(() => {
    const tab = activeTab;
    untrack(() => {
      if (navState.tab !== tab) {
        navState = { ...navState, tab };
      }
    });
  });

  $effect(() => {
    const snap: WorkspaceSnapshot = {
      paneId,
      rawTarget: session.rawTarget,
      baseUrl: session.client?.baseUrl ?? '',
      binaryName: session.status?.binary_name ?? null,
      version: session.status?.version ?? null,
      phase: session.phase,
      statusBadgeColor: session.statusBadgeColor,
      statusBadgeText: session.statusBadgeText,
      navState,
    };
    untrack(() => {
      onStateSnapshot(snap);
    });
  });

  $effect(() => {
    return () => {
      session.dispose();
    };
  });
</script>

<div class="@container min-w-0 space-y-4">
  <Card.Root color="bright-black" class="py-3">
    <Card.Content class="space-y-2.5">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex min-w-0 flex-wrap items-center gap-2">
          <Badge color={isActivePane && isSplit ? 'cyan' : 'white'}>
            {session.client ? formatServerTag(session.client.baseUrl) : `pane ${paneSlot + 1}`}
          </Badge>
          <Badge color={session.statusBadgeColor}>{session.statusBadgeText}</Badge>
          {#if session.status}
            <span class="min-w-0 truncate font-mono text-sm font-black">{session.status.binary_name}</span>
            <Badge color="yellow">v{session.status.version}</Badge>
          {/if}
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          {#if session.status}
            <div class="flex items-center gap-1">
              <Badge color="white">RO</Badge>
              <CopyButton
                value={session.status.mcp_ro_url}
                variant="icon"
                color="cyan"
                size="sm"
                aria-label="Copy read-only MCP URL"
              />
            </div>
            <div class="flex items-center gap-1">
              <Badge color="white">RW</Badge>
              <CopyButton
                value={session.status.mcp_rw_url}
                variant="icon"
                color="magenta"
                size="sm"
                aria-label="Copy read-write MCP URL"
              />
            </div>

            <Button
              color="cyan"
              size="sm"
              disabled={session.exportLoading || session.phase !== 'ready'}
              onclick={() => void session.exportSnapshot()}
            >
              {#if session.exportLoading}
                <Spinner />
              {:else}
                <DownloadIcon />
              {/if}
              Export
            </Button>
          {/if}

          {#if session.canShutdown}
            <ConfirmDialog
              title="Shut down ghidraMCP?"
              description="Gracefully stops the headless Ghidra server on this port. Committed versions stay persisted in the work directory."
              confirmText="Shutdown"
              color="yellow"
              actionColor="red"
              cancelColor="white"
              onConfirm={() => void session.shutdown()}
            >
              {#snippet children({ props })}
                <Button {...props} color="red" size="sm" disabled={!session.canShutdown}>
                  <PowerIcon />
                  Shutdown
                </Button>
              {/snippet}
            </ConfirmDialog>
          {/if}

          {#if session.client && session.rawTarget}
            <Button
              color="blue"
              size="sm"
              href={buildServerQuery(session.rawTarget)}
              target="_blank"
              rel="noopener"
              aria-label={`Open ${session.client.baseUrl} in new tab`}
            >
              <ExternalLinkIcon />
              Tab
            </Button>
          {/if}

          {#if isSplit}
            <Button color="yellow" size="sm" onclick={onToggleFocus}>
              {#if isFocused}
                <Minimize2Icon />
                Split
              {:else}
                <Maximize2Icon />
                Focus
              {/if}
            </Button>
          {/if}

          {#if canClose}
            <Button color="red" size="icon-sm" aria-label="Close pane" onclick={onClose}>
              <XIcon />
            </Button>
          {/if}
        </div>
      </div>

      {#if session.client}
        <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span>SSE: {session.sseState}</span>
          {#if session.lastEvent}
            <span>·</span>
            <span>last: {session.lastEvent.event} @ {session.lastEvent.at}</span>
          {/if}
          {#if session.status}
            <span>·</span>
            <span>sha256:{session.status.binary_sha256.slice(0, 12)}</span>
          {/if}
        </div>
      {/if}

      {#if session.actionError}
        <Alert.Root color="red">
          <ShieldAlertIcon />
          <Alert.Title>Request error</Alert.Title>
          <Alert.Description>{session.actionError}</Alert.Description>
        </Alert.Root>
      {/if}

      {#if session.exportNotice}
        <Alert.Root color="green">
          <DownloadIcon />
          <Alert.Title>Snapshot exported to {session.exportNotice.dir} (v{session.exportNotice.version})</Alert.Title>
          <Alert.Description class="font-mono text-xs">
            {session.exportNotice.files.length} files · {session.exportNotice.counts.functions ?? 0} functions ·
            {session.exportNotice.counts.source_files ?? 0} source files · {session.exportNotice.counts.edges ?? 0} edges
          </Alert.Description>
        </Alert.Root>
      {/if}
    </Card.Content>
  </Card.Root>

  {#if session.phase === 'ready' && session.client && session.status}
    {#key session.client.baseUrl}
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
            {paneSlot}
            client={session.client}
            versions={session.versions}
            currentVersion={session.status.version}
            segments={session.status.segments}
            active={activeTab === 'scrubber'}
            versionCache={session.versionCache}
            ensureVersionDetail={session.ensureVersionDetail}
            focusRequest={focusScrubReq}
            initialNav={navState}
            onInspectFunction={jumpToFunction}
            onNavChange={handleNavPatch}
          />
        </Tabs.Content>

        <Tabs.Content value="functions">
          <FunctionInspector
            client={session.client}
            currentVersion={session.status.version}
            segments={session.status.segments}
            active={activeTab === 'functions'}
            touchedAddresses={session.touchedAddresses}
            lastVersionEvent={session.lastVersionEvent}
            inspectRequest={focusInspectReq}
            initialNav={navState}
            onScrubFunction={jumpToScrubber}
            onOpenMemory={jumpToMemory}
            onNavChange={handleNavPatch}
          />
        </Tabs.Content>

        <Tabs.Content value="explore">
          <ExplorePanel
            client={session.client}
            currentVersion={session.status.version}
            segments={session.status.segments}
            active={activeTab === 'explore'}
            memoryRequest={focusMemoryReq}
            initialNav={navState}
            onInspectFunction={jumpToFunction}
            onNavChange={handleNavPatch}
          />
        </Tabs.Content>

        <Tabs.Content value="binary">
          <BinaryOverview status={session.status} onInspectFunction={jumpToFunction} onOpenMemory={jumpToMemory} />
        </Tabs.Content>
      </Tabs.Root>
    {/key}
  {:else}
    <div class={isSplit && !isFocused ? 'py-2' : 'mx-auto max-w-2xl py-4'}>
      <Card.Root color="bright-black">
        <Card.Header>
          <Card.Title class="flex items-center gap-2">
            {#if session.phase === 'connecting' || session.phase === 'analyzing'}
              <Spinner color="yellow" />
            {/if}
            <span>
              {#if session.phase === 'disconnected'}
                Tap into headless Ghidra
              {:else if session.phase === 'connecting'}
                Connecting to server...
              {:else if session.phase === 'analyzing'}
                Analyzing binary in Ghidra...
              {:else if session.phase === 'recovery_required'}
                Workspace recovery required
              {:else if session.phase === 'stopped'}
                Server stopped
              {:else}
                Connection failed
              {/if}
            </span>
          </Card.Title>
          <Card.Description>
            Enter the port printed by `just run` (or an HTTP URL). Open another pane or tab anytime to compare multiple
            MCPs side-by-side.
          </Card.Description>
        </Card.Header>

        <Card.Content class="space-y-4">
          {#if session.phase === 'error' || session.phase === 'recovery_required'}
            <Alert.Root color="red">
              <ShieldAlertIcon />
              <Alert.Title>
                {session.phase === 'recovery_required' ? 'Workspace recovery required' : 'Connection error'}
              </Alert.Title>
              <Alert.Description>{session.phaseDetail}</Alert.Description>
            </Alert.Root>
          {:else if session.phase === 'stopped' || (session.phaseDetail && (session.phase === 'connecting' || session.phase === 'analyzing'))}
            <Alert.Root color={session.phase === 'stopped' ? 'yellow' : 'cyan'}>
              <Alert.Title>{session.phase === 'stopped' ? 'Stopped' : 'Status'}</Alert.Title>
              <Alert.Description>{session.phaseDetail}</Alert.Description>
            </Alert.Root>
          {/if}

          <ServerConnectForm
            bind:target={targetInput}
            bind:token={tokenInput}
            error={localFormError}
            showSplit
            showRetry={session.phase === 'error' || session.phase === 'stopped'}
            onConnect={(raw, token) => connectTarget(raw, token, raw.trim() === session.rawTarget)}
            onSplit={(raw, token) => {
              localFormError = null;
              onSplitServer(raw, token, (msg) => {
                localFormError = msg;
              });
            }}
            onOpenTab={(raw) => {
              localFormError = null;
              onOpenInNewTab(raw, (msg) => {
                localFormError = msg;
              });
            }}
            onRetry={() => connectTarget(undefined, undefined, true)}
          />

          {#if savedServers.length > 0}
            <div class="space-y-2 pt-2">
              <div class="font-mono text-xs font-bold">Saved servers ({savedServers.length})</div>
              {#each savedServers as srv (srv.baseUrl)}
                {@const alreadyOpen = activeUrls.includes(srv.baseUrl)}
                <Item.Root color="white" size="sm" class="mb-0">
                  <Item.Content>
                    <Item.Header>
                      <Item.Title class="font-mono">{srv.label || formatServerTag(srv.baseUrl)}</Item.Title>
                      {#if alreadyOpen}
                        <Badge color="cyan">open</Badge>
                      {/if}
                    </Item.Header>
                    <Item.Description class="font-mono text-xs">{srv.baseUrl}</Item.Description>
                  </Item.Content>
                  <Item.Actions>
                    <Button color="cyan" size="sm" onclick={() => onConnectSaved(srv)}>Connect</Button>
                    <Button
                      color="magenta"
                      size="sm"
                      aria-label={`Open ${srv.baseUrl} in split pane`}
                      onclick={() => onSplitServer(srv.raw)}
                    >
                      <Columns2Icon />
                      Split
                    </Button>
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
                      onclick={() => onRemoveServer(srv.baseUrl)}
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
