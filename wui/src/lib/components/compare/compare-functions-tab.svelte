<script lang="ts">
  import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
  import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
  import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
  import ChevronUpIcon from '@lucide/svelte/icons/chevron-up';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Table from '#lib/components/ui/table/index.js';
  import { formatBytes, SHIKI_CONFIG } from '#lib/ghidra-api.ts';
  import {
    alignVariables,
    computeUnifiedDiff,
    getSnapshotPaletteEntry,
    type FunctionCompareRow,
    type FunctionFilter,
    type LoadedSnapshot,
    type SnapshotFunction,
  } from '#lib/snapshot-compare.ts';
  import { untrack } from 'svelte';
  import { SvelteMap, SvelteSet } from 'svelte/reactivity';

  let {
    snapshots,
    baselineIndex,
    rows,
    selectedKey,
    filter,
    onSelectKey,
    onFilterChange,
  }: {
    snapshots: LoadedSnapshot[];
    baselineIndex: number;
    rows: FunctionCompareRow[];
    selectedKey: string;
    filter: FunctionFilter;
    onSelectKey: (key: string) => void;
    onFilterChange: (filter: FunctionFilter) => void;
  } = $props();

  const uid = $props.id();

  let searchQuery = $state('');
  let pickerOpen = $state(true);
  let codeViewMode = $state<'side-by-side' | 'diff'>('side-by-side');

  const lazySourceCache = new SvelteMap<string, string>();
  const lazySourceLoading = new SvelteSet<string>();
  const lazySourceMissing = new SvelteSet<string>();

  const safeBaselineIndex = $derived(baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0);

  const statusCounts = $derived.by(() => {
    let identical = 0;
    let missing = 0;
    for (const r of rows) {
      if (r.status === 'identical') identical++;
      else if (r.status === 'missing') missing++;
    }
    const shared = rows.length - missing;
    return { all: rows.length, shared, missing, identical };
  });

  const filteredRows = $derived.by(() => {
    const q = searchQuery.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter === 'shared' && r.status === 'missing') return false;
      if (filter === 'missing' && r.status !== 'missing') return false;
      if (filter === 'identical' && r.status !== 'identical') return false;
      if (!q) return true;
      if (r.key.toLowerCase().includes(q) || r.displayName.toLowerCase().includes(q)) return true;
      return r.entries.some(
        (fn) => fn && (fn.name.toLowerCase().includes(q) || fn.entry_address.toLowerCase().includes(q)),
      );
    });
  });

  const activeRow = $derived(rows.find((r) => r.key === selectedKey) ?? filteredRows[0] ?? rows[0] ?? null);

  const activeFilteredIndex = $derived(activeRow ? filteredRows.findIndex((r) => r.key === activeRow.key) : -1);

  function stepFunction(delta: -1 | 1) {
    if (filteredRows.length === 0) return;
    const currentIdx = activeFilteredIndex >= 0 ? activeFilteredIndex : 0;
    const nextIdx = (currentIdx + delta + filteredRows.length) % filteredRows.length;
    onSelectKey(filteredRows[nextIdx].key);
  }

  function sourceCacheKey(snap: LoadedSnapshot, relPath: string): string {
    return `${snap.id}::${snap.dirPath}::${relPath}`;
  }

  function resolveFunctionCode(snap: LoadedSnapshot, fn: SnapshotFunction | null): string | null {
    if (!fn?.src_file) return null;
    if (Object.hasOwn(snap.sources, fn.src_file)) return snap.sources[fn.src_file];
    return lazySourceCache.get(sourceCacheKey(snap, fn.src_file)) ?? null;
  }

  $effect(() => {
    const current = activeRow;
    const snaps = snapshots;
    if (!current) return;

    untrack(() => {
      snaps.forEach((snap, idx) => {
        const fn = current.entries[idx];
        const relPath = fn?.src_file;
        if (!relPath) return;
        if (Object.hasOwn(snap.sources, relPath)) return;
        const key = sourceCacheKey(snap, relPath);
        if (lazySourceCache.has(key) || lazySourceLoading.has(key) || lazySourceMissing.has(key)) return;

        lazySourceLoading.add(key);
        void snap
          .loadSource(relPath)
          .then((text) => {
            if (text !== null) {
              lazySourceCache.set(key, text);
            } else {
              lazySourceMissing.add(key);
            }
          })
          .finally(() => {
            lazySourceLoading.delete(key);
          });
      });
    });
  });

  function formatDwarfRange(fn: SnapshotFunction): string | null {
    const lines = fn.lines ?? [];
    if (lines.length === 0) return null;
    const nums = lines.map((l) => l.line).filter((n): n is number => typeof n === 'number' && n > 0);
    const file = lines.find((l) => l.file)?.file ?? 'src';
    const base = file.split('/').pop() ?? file;
    if (nums.length === 0) return base;
    const min = Math.min(...nums);
    const max = Math.max(...nums);
    return min === max ? `${base}:${min}` : `${base}:${min}-${max}`;
  }

  const variableRows = $derived(activeRow ? alignVariables(activeRow.entries) : []);

  const codeGridClass = $derived(
    snapshots.length >= 3
      ? 'grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3'
      : 'grid grid-cols-1 gap-4 lg:grid-cols-2',
  );
</script>

<div class="space-y-4">
  <Card.Root color="bright-black" class="min-w-0">
    <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <Card.Title class="font-mono text-base">Functions (by offset)</Card.Title>
        <Badge color="yellow">{filteredRows.length}/{rows.length}</Badge>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <ButtonGroup.Root aria-label="Step filtered functions">
          <Button
            color="white"
            size="sm"
            disabled={filteredRows.length <= 1}
            aria-label="Previous function"
            onclick={() => stepFunction(-1)}
          >
            <ChevronLeftIcon />
            Prev
          </Button>
          <Button
            color="white"
            size="sm"
            disabled={filteredRows.length <= 1}
            aria-label="Next function"
            onclick={() => stepFunction(1)}
          >
            Next
            <ChevronRightIcon />
          </Button>
        </ButtonGroup.Root>

        <Button
          color={pickerOpen ? 'cyan' : 'white'}
          size="sm"
          aria-expanded={pickerOpen}
          onclick={() => (pickerOpen = !pickerOpen)}
        >
          {#if pickerOpen}
            <ChevronUpIcon />
            Hide list
          {:else}
            <ChevronDownIcon />
            Show list
          {/if}
        </Button>
      </div>
    </Card.Header>

    {#if pickerOpen}
      <Card.Content class="space-y-3">
        <div class="flex flex-wrap items-end justify-between gap-3">
          <Field.Field class="min-w-56 flex-1 sm:max-w-sm">
            <Field.Label for={`${uid}-search`}>Filter</Field.Label>
            <Input
              id={`${uid}-search`}
              color="white"
              bind:value={searchQuery}
              placeholder="Name or offset (e.g. 001129)..."
            />
          </Field.Field>

          <div class="flex flex-wrap gap-1.5">
            {#each [['all', 'All', statusCounts.all, 'cyan'], ['shared', 'Shared', statusCounts.shared, 'blue'], ['missing', 'Missing', statusCounts.missing, 'red'], ['identical', 'Identical', statusCounts.identical, 'green']] as const as [val, label, count, activeColor] (val)}
              <Button
                color={filter === val ? activeColor : 'white'}
                size="sm"
                aria-pressed={filter === val}
                onclick={() => onFilterChange(val)}
              >
                {label} ({count})
              </Button>
            {/each}
          </div>
        </div>

        {#if filteredRows.length > 0}
          <div class="grid grid-cols-1 gap-2 p-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {#each filteredRows as row (row.key)}
              {@const isSelected = activeRow?.key === row.key}
              {@const visibleReasons = row.diffReasons.filter((r) => r !== 'missing').slice(0, 2)}
              <Item.Root
                color={isSelected ? 'cyan' : 'white'}
                size="sm"
                pressable
                class="mb-0 w-full cursor-pointer text-left"
              >
                {#snippet child({ props })}
                  <button {...props} type="button" onclick={() => onSelectKey(row.key)}>
                    <Item.Content class="space-y-1">
                      <Item.Header>
                        <Item.Title class="truncate font-mono text-xs font-bold">{row.displayName}</Item.Title>
                        {#if row.status === 'missing'}
                          <Badge color="red">missing</Badge>
                        {:else if row.status === 'identical'}
                          <Badge color="green">identical</Badge>
                        {/if}
                      </Item.Header>
                      <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                        <span>@{row.key}</span>
                        <span>·</span>
                        <span>{formatBytes(row.maxSize)}</span>
                        {#each visibleReasons as reason (reason)}
                          <Badge color="bright-black">{reason}</Badge>
                        {/each}
                      </div>
                    </Item.Content>
                  </button>
                {/snippet}
              </Item.Root>
            {/each}
          </div>
        {:else}
          <p class="py-4 text-center font-mono text-xs">No functions match this filter.</p>
        {/if}
      </Card.Content>
    {/if}
  </Card.Root>

  <div class="min-w-0 space-y-4">
    {#if activeRow}
      {@const baseSnap = snapshots[safeBaselineIndex]}
      {@const baseFn = activeRow.entries[safeBaselineIndex]}
      {@const baseCode = resolveFunctionCode(baseSnap, baseFn) ?? ''}
      {@const headerReasons = activeRow.diffReasons.filter((r) => r !== 'missing')}

      <Card.Root color="bright-black" class="min-w-0">
        <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-3">
          <div class="min-w-0 space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <Badge color="cyan">@{activeRow.key}</Badge>
              {#if activeRow.status === 'missing'}
                <Badge color="red">missing</Badge>
              {:else if activeRow.status === 'identical'}
                <Badge color="green">identical</Badge>
              {/if}
              {#each headerReasons as reason (reason)}
                <Badge color="yellow">{reason}</Badge>
              {/each}
            </div>
            <Card.Title class="truncate font-mono text-base">{activeRow.displayName}</Card.Title>
          </div>

          <ButtonGroup.Root aria-label="Function comparison mode">
            <Button
              color={codeViewMode === 'side-by-side' ? 'cyan' : 'white'}
              size="sm"
              aria-pressed={codeViewMode === 'side-by-side'}
              onclick={() => (codeViewMode = 'side-by-side')}
            >
              Side-by-side C
            </Button>
            <Button
              color={codeViewMode === 'diff' ? 'yellow' : 'white'}
              size="sm"
              aria-pressed={codeViewMode === 'diff'}
              onclick={() => (codeViewMode = 'diff')}
            >
              Diff vs {baseSnap.label}
            </Button>
          </ButtonGroup.Root>
        </Card.Header>
      </Card.Root>

      {#if codeViewMode === 'side-by-side'}
        <div class={codeGridClass}>
          {#each snapshots as snap, idx (snap.id)}
            {@const fn = activeRow.entries[idx]}
            {@const palette = getSnapshotPaletteEntry(idx)}
            {@const codeText = resolveFunctionCode(snap, fn)}
            {@const loadingCode = Boolean(fn?.src_file && lazySourceLoading.has(sourceCacheKey(snap, fn.src_file)))}
            {@const dwarfLabel = fn ? formatDwarfRange(fn) : null}

            <Card.Root color="white" class="min-w-0">
              <Card.Header class="space-y-2">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <Badge color={palette.color}>{snap.label}</Badge>
                    {#if idx === safeBaselineIndex}
                      <Badge color="yellow">Baseline</Badge>
                    {/if}
                  </div>
                  {#if fn}
                    <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                      <Badge color="bright-black">@{fn.entry_address}</Badge>
                      <Badge color="bright-black">{formatBytes(fn.size)}</Badge>
                      {#if dwarfLabel}
                        <Badge color="green">{dwarfLabel}</Badge>
                      {/if}
                    </div>
                  {:else}
                    <Badge color="red">Missing</Badge>
                  {/if}
                </div>

                {#if fn}
                  <p class="font-mono text-xs font-bold break-all">{fn.signature}</p>
                {/if}
              </Card.Header>

              <Card.Content class="min-w-0">
                {#if !fn}
                  <Alert.Root color="red" noShadow>
                    <Alert.Title>Function not present</Alert.Title>
                    <Alert.Description>No function entry at offset @{activeRow.key} in {snap.label}.</Alert.Description>
                  </Alert.Root>
                {:else if loadingCode}
                  <div class="flex items-center gap-2 py-6 font-mono text-xs">
                    <Spinner color={palette.color} />
                    <span>Loading {fn.src_file}...</span>
                  </div>
                {:else if codeText !== null}
                  <CodeBlock
                    color="white"
                    headerColor={palette.color}
                    lang="c"
                    title={fn.src_file ?? `${fn.name}.c`}
                    code={codeText}
                    shiki={SHIKI_CONFIG}
                    lines={28}
                    copy
                  />
                {:else}
                  <Alert.Root color="yellow" noShadow>
                    <Alert.Title>Decompiled C unavailable</Alert.Title>
                    <Alert.Description>
                      Status: {fn.decompile_status ?? 'unknown'}
                      {fn.decompile_error ? ` — ${fn.decompile_error}` : ''}
                    </Alert.Description>
                  </Alert.Root>
                {/if}
              </Card.Content>
            </Card.Root>
          {/each}
        </div>
      {:else}
        <div class="space-y-4">
          {#each snapshots as snap, idx (snap.id)}
            {#if idx !== safeBaselineIndex}
              {@const fn = activeRow.entries[idx]}
              {@const palette = getSnapshotPaletteEntry(idx)}
              {@const targetCode = resolveFunctionCode(snap, fn) ?? ''}
              {@const diffRes = computeUnifiedDiff(baseSnap.label, snap.label, baseCode, targetCode)}

              {#if diffRes.identical}
                <Alert.Root color="green">
                  <Alert.Title>{baseSnap.label} → {snap.label}</Alert.Title>
                  <Alert.Description>Pseudocode is identical for @{activeRow.key}.</Alert.Description>
                </Alert.Root>
              {:else}
                <CodeBlock
                  color="yellow"
                  headerColor={palette.color}
                  lang="diff"
                  title={`${baseSnap.label} → ${snap.label} (+${diffRes.added} / -${diffRes.removed})`}
                  code={diffRes.diff}
                  shiki={SHIKI_CONFIG}
                  lines={34}
                  copy
                />
              {/if}
            {/if}
          {/each}
        </div>
      {/if}

      <Card.Root color="bright-black" class="min-w-0">
        <Card.Header class="flex flex-row items-center justify-between gap-2">
          <Card.Title class="font-mono text-base">Variables Alignment ({variableRows.length})</Card.Title>
          <Badge color="blue">matched by storage</Badge>
        </Card.Header>
        <Card.Content>
          {#if variableRows.length > 0}
            <Table.Root headerColor="blue" rowColor="white">
              <Table.Header>
                <Table.Row>
                  <Table.Head>Kind / Storage</Table.Head>
                  <Table.Head>Status</Table.Head>
                  {#each snapshots as snap, idx (snap.id)}
                    <Table.Head>
                      <Badge color={getSnapshotPaletteEntry(idx).color}>{snap.label}</Badge>
                    </Table.Head>
                  {/each}
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each variableRows as vr (vr.key)}
                  <Table.Row>
                    <Table.Cell class="font-mono text-xs">
                      <Badge color={vr.kind === 'parameter' ? 'cyan' : 'yellow'}>{vr.kind}</Badge>
                      <span class="ml-1">{vr.storage}</span>
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs">
                      {#if vr.status === 'identical'}
                        <Badge color="green">identical</Badge>
                      {:else if vr.status === 'missing'}
                        <Badge color="red">missing</Badge>
                      {:else}
                        <span>—</span>
                      {/if}
                    </Table.Cell>
                    {#each vr.entries as v, idx (snapshots[idx]?.id ?? idx)}
                      <Table.Cell class="font-mono text-xs">
                        {#if v}
                          <div class="font-bold">{v.name}</div>
                          <div>{v.data_type}</div>
                        {:else}
                          <span>-</span>
                        {/if}
                      </Table.Cell>
                    {/each}
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          {:else}
            <p class="py-3 font-mono text-xs">No exported variables recorded for this function.</p>
          {/if}
        </Card.Content>
      </Card.Root>
    {:else}
      <Alert.Root color="blue">
        <Alert.Title>No function selected</Alert.Title>
        <Alert.Description
          >Choose a function from the selector above to compare pseudocode and variables.</Alert.Description
        >
      </Alert.Root>
    {/if}
  </div>
</div>
