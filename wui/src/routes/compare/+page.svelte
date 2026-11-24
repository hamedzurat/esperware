<script lang="ts">
  import CodeIcon from '@lucide/svelte/icons/code';
  import FileTypeIcon from '@lucide/svelte/icons/file-type';
  import GitCompareArrowsIcon from '@lucide/svelte/icons/git-compare-arrows';
  import NetworkIcon from '@lucide/svelte/icons/network';
  import TagsIcon from '@lucide/svelte/icons/tags';
  import TerminalIcon from '@lucide/svelte/icons/terminal';
  import CompareCallgraphTab from '#lib/components/compare/compare-callgraph-tab.svelte';
  import CompareFunctionsTab from '#lib/components/compare/compare-functions-tab.svelte';
  import CompareOverview from '#lib/components/compare/compare-overview.svelte';
  import CompareSymbolsTab from '#lib/components/compare/compare-symbols-tab.svelte';
  import CompareTypesTab from '#lib/components/compare/compare-types-tab.svelte';
  import SnapshotSourcesBar from '#lib/components/compare/snapshot-sources-bar.svelte';
  import { BackgroundPattern } from '#lib/components/ui/background-pattern/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { ThemePicker } from '#lib/components/ui/style/index.js';
  import * as Tabs from '#lib/components/ui/tabs/index.js';
  import {
    alignFunctions,
    buildCompareUrl,
    loadSnapshotFromFiles,
    loadSnapshotFromPath,
    parseCompareUrl,
    type FunctionFilter,
    type LoadedSnapshot,
    type SnapshotSlotConfig,
  } from '#lib/snapshot-compare.ts';
  import { onMount, untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';

  let nextSlotId = 1;
  const activeControllers = new SvelteMap<string, AbortController>();

  function makeSlot(label: string, path = ''): SnapshotSlotConfig {
    return {
      id: `snap-${nextSlotId++}`,
      label,
      path,
      status: 'idle',
      error: null,
      snapshot: null,
    };
  }

  let slots = $state<SnapshotSlotConfig[]>([makeSlot('Stripped'), makeSlot('Unstripped')]);
  let baselineIndex = $state(0);
  let activeTab = $state<'functions' | 'types' | 'symbols' | 'callgraph'>('functions');
  let selectedFnKey = $state('');
  let fnFilter = $state<FunctionFilter>('all');

  const readyPairs = $derived(
    slots
      .map((slot, slotIdx) => ({ slot, slotIdx, snap: slot.snapshot }))
      .filter((entry): entry is { slot: SnapshotSlotConfig; slotIdx: number; snap: LoadedSnapshot } =>
        Boolean(entry.snap),
      ),
  );

  const loadedSnapshots = $derived(readyPairs.map((entry) => entry.snap));

  const effectiveBaselineIndex = $derived.by(() => {
    const pos = readyPairs.findIndex((entry) => entry.slotIdx === baselineIndex);
    return pos >= 0 ? pos : 0;
  });

  const functionRows = $derived(alignFunctions(loadedSnapshots, effectiveBaselineIndex));
  const anyLoading = $derived(slots.some((s) => s.status === 'loading'));

  const pageTitle = $derived.by(() => {
    if (loadedSnapshots.length >= 2) {
      return `Compare (${loadedSnapshots.map((s) => s.label).join(' vs ')}) — Esperware`;
    }
    return 'Snapshot Compare — Esperware';
  });

  function syncUrlToSlots() {
    if (typeof window === 'undefined') return;
    const nextSearch = buildCompareUrl(slots, baselineIndex);
    const nextHref = `${window.location.pathname}${nextSearch}`;
    if (`${window.location.pathname}${window.location.search}` !== nextHref) {
      window.history.replaceState(null, '', nextHref);
    }
  }

  function updateSlot(id: string, patch: Partial<SnapshotSlotConfig>) {
    slots = slots.map((s) => (s.id === id ? { ...s, ...patch } : s));
  }

  function handleUpdateLabel(id: string, label: string) {
    const slot = slots.find((s) => s.id === id);
    if (!slot) return;
    const nextSnap = slot.snapshot
      ? { ...slot.snapshot, label: label.trim() || slot.snapshot.manifest.binary_name }
      : null;
    updateSlot(id, { label, snapshot: nextSnap });
    syncUrlToSlots();
  }

  function handleUpdatePath(id: string, path: string) {
    updateSlot(id, { path });
  }

  function handleAddSlot() {
    slots = [...slots, makeSlot(`Snapshot ${slots.length + 1}`)];
  }

  function handleRemoveSlot(id: string) {
    if (slots.length <= 2) return;
    activeControllers.get(id)?.abort();
    activeControllers.delete(id);
    const idx = slots.findIndex((s) => s.id === id);
    slots = slots.filter((s) => s.id !== id);
    if (baselineIndex >= slots.length) {
      baselineIndex = 0;
    } else if (idx >= 0 && idx < baselineIndex) {
      baselineIndex = Math.max(0, baselineIndex - 1);
    }
    syncUrlToSlots();
  }

  function handleSelectBaseline(idx: number) {
    baselineIndex = idx;
    syncUrlToSlots();
  }

  function handleSwapFirstTwo() {
    if (slots.length < 2) return;
    const [first, second, ...rest] = slots;
    slots = [second, first, ...rest];
    if (baselineIndex === 0) baselineIndex = 1;
    else if (baselineIndex === 1) baselineIndex = 0;
    syncUrlToSlots();
  }

  async function loadSlotPath(id: string) {
    const slot = slots.find((s) => s.id === id);
    if (!slot || !slot.path.trim()) return;

    activeControllers.get(id)?.abort();
    const ctrl = new AbortController();
    activeControllers.set(id, ctrl);

    const requestedPath = slot.path.trim();
    const requestedLabel = slot.label;
    updateSlot(id, { status: 'loading', error: null });
    syncUrlToSlots();

    try {
      const snap = await loadSnapshotFromPath(requestedPath, requestedLabel, id, ctrl.signal);
      if (ctrl.signal.aborted) return;
      updateSlot(id, {
        label: requestedLabel.trim() || snap.label,
        path: snap.dirPath,
        status: 'ready',
        error: null,
        snapshot: snap,
      });
      syncUrlToSlots();
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      updateSlot(id, {
        status: 'error',
        error: err instanceof Error ? err.message : 'Failed to load snapshot path.',
        snapshot: null,
      });
    } finally {
      if (activeControllers.get(id) === ctrl) {
        activeControllers.delete(id);
      }
    }
  }

  async function loadSlotFolder(id: string, files: FileList) {
    const slot = slots.find((s) => s.id === id);
    if (!slot) return;

    activeControllers.get(id)?.abort();
    activeControllers.delete(id);
    updateSlot(id, { status: 'loading', error: null });

    try {
      const snap = await loadSnapshotFromFiles(files, slot.label, id);
      updateSlot(id, {
        label: slot.label.trim() || snap.label,
        status: 'ready',
        error: null,
        snapshot: snap,
      });
    } catch (err) {
      updateSlot(id, {
        status: 'error',
        error: err instanceof Error ? err.message : 'Failed to load folder snapshot.',
        snapshot: null,
      });
    }
  }

  function loadAllPaths() {
    for (const slot of slots) {
      if (slot.path.trim()) {
        void loadSlotPath(slot.id);
      }
    }
  }

  function jumpToFunctions(filter: FunctionFilter, offset?: string) {
    fnFilter = filter;
    if (offset) {
      selectedFnKey = offset;
    } else {
      const firstMatch = functionRows.find((r) => {
        if (filter === 'all') return true;
        if (filter === 'shared') return r.status !== 'missing';
        return r.status === filter;
      });
      if (firstMatch) selectedFnKey = firstMatch.key;
    }
    activeTab = 'functions';
  }

  onMount(() => {
    const parsed = parseCompareUrl(window.location.search);
    untrack(() => {
      if (parsed.entries.length > 0) {
        const nextSlots = parsed.entries.map((entry, idx) =>
          makeSlot(
            entry.label ?? (idx === 0 ? 'Stripped' : idx === 1 ? 'Unstripped' : `Snapshot ${idx + 1}`),
            entry.dir,
          ),
        );
        while (nextSlots.length < 2) {
          nextSlots.push(makeSlot(nextSlots.length === 1 ? 'Unstripped' : `Snapshot ${nextSlots.length + 1}`));
        }
        slots = nextSlots;
        baselineIndex = parsed.baselineIndex < nextSlots.length ? parsed.baselineIndex : 0;
        for (const s of nextSlots) {
          if (s.path.trim()) {
            void loadSlotPath(s.id);
          }
        }
      }
    });

    return () => {
      for (const ctrl of activeControllers.values()) {
        ctrl.abort();
      }
      activeControllers.clear();
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
            <h1 class="my-0 flex items-center gap-2 font-mono text-sm font-black tracking-tight">
              <GitCompareArrowsIcon class="size-4" />
              SNAPSHOT COMPARE
            </h1>
            {#if loadedSnapshots.length >= 2}
              <Badge color="green">{loadedSnapshots.length} loaded</Badge>
            {/if}
          </div>

          <div class="flex shrink-0 items-center gap-2">
            <Button color="white" size="sm" href="/">MCP Deck</Button>
            <ThemePicker backgroundColor="yellow" />
          </div>
        </Card.Content>
      </Card.Root>
    </div>
  </section>

  <section class="neoretro-border-b relative isolate overflow-hidden py-4">
    <BackgroundPattern pattern="cross" size={20} rotation={45} />
    <div class="relative z-10 container mx-auto max-w-7xl px-4">
      <SnapshotSourcesBar
        {slots}
        {baselineIndex}
        busy={anyLoading}
        onUpdateLabel={handleUpdateLabel}
        onUpdatePath={handleUpdatePath}
        onAddSlot={handleAddSlot}
        onRemoveSlot={handleRemoveSlot}
        onSelectBaseline={handleSelectBaseline}
        onLoadSlotPath={(id) => void loadSlotPath(id)}
        onLoadSlotFolder={(id, files) => void loadSlotFolder(id, files)}
        onLoadAll={loadAllPaths}
        onSwapFirstTwo={handleSwapFirstTwo}
      />
    </div>
  </section>

  <section class="relative isolate flex-1 py-6">
    <BackgroundPattern pattern="dots" size={16} />
    <div
      class={loadedSnapshots.length >= 2
        ? 'relative z-10 w-full space-y-6 px-4'
        : 'relative z-10 container mx-auto max-w-7xl space-y-6 px-4'}
    >
      {#if loadedSnapshots.length < 2}
        <Card.Root color="bright-black" class="min-w-0">
          <Card.Header>
            <Card.Title class="font-mono text-lg">Load 2 or more exported snapshots to compare</Card.Title>
          </Card.Header>
          <Card.Content class="space-y-3 font-mono text-xs">
            <p>
              Paste 2+ local export directories above and press <strong>Load all</strong>, or pick folders directly from
              your browser. Expected <code>export_layout_version: 2</code> layout:
            </p>
            <div class="flex flex-wrap gap-2">
              <Badge color="cyan">manifest.json</Badge>
              <Badge color="green">functions.jsonl</Badge>
              <Badge color="yellow">src/*.c</Badge>
              <Badge color="magenta">types.h</Badge>
              <Badge color="blue">symbols.json</Badge>
              <Badge color="white">callgraph.jsonl</Badge>
            </div>
            <p>
              Tip: you can also open <code>/compare?dir=/path/to/stripped&amp;dir=/path/to/unstripped</code> directly.
            </p>
          </Card.Content>
        </Card.Root>
      {:else}
        <CompareOverview
          snapshots={loadedSnapshots}
          baselineIndex={effectiveBaselineIndex}
          {functionRows}
          onJumpToFunctions={jumpToFunctions}
        />

        <Tabs.Root bind:value={activeTab} activeColor="cyan" inactiveColor="white" class="min-w-0">
          <Tabs.List class="flex-wrap">
            <Tabs.Trigger value="functions" class="gap-1.5 font-mono text-xs">
              <CodeIcon class="size-3.5" />
              Functions ({functionRows.length})
            </Tabs.Trigger>
            <Tabs.Trigger value="types" class="gap-1.5 font-mono text-xs">
              <FileTypeIcon class="size-3.5" />
              Types
            </Tabs.Trigger>
            <Tabs.Trigger value="symbols" class="gap-1.5 font-mono text-xs">
              <TagsIcon class="size-3.5" />
              Symbols
            </Tabs.Trigger>
            <Tabs.Trigger value="callgraph" class="gap-1.5 font-mono text-xs">
              <NetworkIcon class="size-3.5" />
              Callgraph
            </Tabs.Trigger>
          </Tabs.List>

          <Tabs.Content value="functions" class="mt-4">
            <CompareFunctionsTab
              snapshots={loadedSnapshots}
              baselineIndex={effectiveBaselineIndex}
              rows={functionRows}
              selectedKey={selectedFnKey}
              filter={fnFilter}
              onSelectKey={(k) => (selectedFnKey = k)}
              onFilterChange={(f) => (fnFilter = f)}
            />
          </Tabs.Content>

          <Tabs.Content value="types" class="mt-4">
            <CompareTypesTab snapshots={loadedSnapshots} baselineIndex={effectiveBaselineIndex} />
          </Tabs.Content>

          <Tabs.Content value="symbols" class="mt-4">
            <CompareSymbolsTab snapshots={loadedSnapshots} baselineIndex={effectiveBaselineIndex} />
          </Tabs.Content>

          <Tabs.Content value="callgraph" class="mt-4">
            <CompareCallgraphTab
              snapshots={loadedSnapshots}
              baselineIndex={effectiveBaselineIndex}
              {functionRows}
              onOpenFunction={(offset) => jumpToFunctions('all', offset)}
            />
          </Tabs.Content>
        </Tabs.Root>
      {/if}
    </div>
  </section>
</div>
