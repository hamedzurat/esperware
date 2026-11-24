<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Chart from '#lib/components/ui/chart/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as Table from '#lib/components/ui/table/index.js';
  import {
    alignSymbols,
    getSnapshotPaletteEntry,
    SYMBOL_CATEGORIES,
    type LoadedSnapshot,
    type SymbolCategory,
  } from '#lib/snapshot-compare.ts';
  import { BarChart } from 'layerchart';

  let {
    snapshots,
    baselineIndex,
  }: {
    snapshots: LoadedSnapshot[];
    baselineIndex: number;
  } = $props();

  const uid = $props.id();

  let activeCategory = $state<SymbolCategory>('globals');
  let searchQuery = $state('');
  let statusFilter = $state<'all' | 'missing' | 'identical'>('all');
  let showAllRows = $state(false);

  const safeBaselineIndex = $derived(baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0);

  const categoryTotals = $derived(
    SYMBOL_CATEGORIES.map((category) => {
      const counts = snapshots.map((s) => s.symbols[category].length);
      return { category, counts, max: Math.max(...counts, 0) };
    }),
  );

  const chartConfig = $derived.by(() => {
    const cfg: Chart.ChartConfig = {};
    snapshots.forEach((snap, idx) => {
      cfg[`s${idx}`] = { label: snap.label, color: getSnapshotPaletteEntry(idx).cssVar };
    });
    return cfg;
  });

  const chartSeries = $derived(
    snapshots.map((snap, idx) => ({
      key: `s${idx}`,
      label: snap.label,
      color: getSnapshotPaletteEntry(idx).cssVar,
    })),
  );

  const chartData = $derived(
    categoryTotals.map((entry) => {
      const row: Record<string, string | number> = { category: entry.category };
      entry.counts.forEach((c, idx) => {
        row[`s${idx}`] = c;
      });
      return row;
    }),
  );

  const alignedRows = $derived(alignSymbols(snapshots, activeCategory));

  const filteredRows = $derived.by(() => {
    const q = searchQuery.trim().toLowerCase();
    return alignedRows.filter((row) => {
      if (statusFilter !== 'all' && row.status !== statusFilter) return false;
      if (!q) return true;
      if (row.addressOrId.toLowerCase().includes(q)) return true;
      return row.items.some(
        (item) =>
          item &&
          (item.primaryName.toLowerCase().includes(q) ||
            item.secondaryType.toLowerCase().includes(q) ||
            item.meta.toLowerCase().includes(q)),
      );
    });
  });

  const visibleRows = $derived(showAllRows ? filteredRows : filteredRows.slice(0, 200));
</script>

<div class="space-y-4">
  <Card.Root color="white" class="min-w-0">
    <Card.Header class="flex flex-row items-center justify-between gap-2">
      <Card.Title class="font-mono text-sm">Symbol Distribution (click a bar to filter category)</Card.Title>
      <Badge color="bright-black">baseline: {snapshots[safeBaselineIndex]?.label}</Badge>
    </Card.Header>
    <Card.Content class="min-w-0">
      <Chart.Container config={chartConfig} class="aspect-auto h-56 w-full min-w-0">
        <BarChart
          data={chartData}
          x="category"
          series={chartSeries}
          seriesLayout="group"
          padding={{ top: 12, right: 12, bottom: 28, left: 40 }}
          onBarClick={(_e, detail) => {
            const cat = (detail.data as { category?: SymbolCategory } | undefined)?.category;
            if (cat) {
              activeCategory = cat;
              showAllRows = false;
            }
          }}
        >
          {#snippet tooltip()}
            <Chart.Tooltip color="white" dataLabelKey="category" />
          {/snippet}
        </BarChart>
      </Chart.Container>
    </Card.Content>
  </Card.Root>

  <Card.Root color="bright-black" class="min-w-0">
    <Card.Content class="flex flex-wrap items-end justify-between gap-4">
      <div class="space-y-2">
        <div class="font-mono text-xs font-bold">Category</div>
        <div class="flex flex-wrap gap-1.5">
          {#each categoryTotals as item (item.category)}
            <Button
              color={activeCategory === item.category ? 'cyan' : 'white'}
              size="sm"
              aria-pressed={activeCategory === item.category}
              onclick={() => {
                activeCategory = item.category;
                showAllRows = false;
              }}
            >
              {item.category} ({item.counts.join(' / ')})
            </Button>
          {/each}
        </div>
      </div>

      <div class="flex flex-wrap items-end gap-2">
        <Field.Field class="min-w-56">
          <Field.Label for={`${uid}-search`}>Filter symbols</Field.Label>
          <Input id={`${uid}-search`} color="white" bind:value={searchQuery} placeholder="Name, address, or value..." />
        </Field.Field>

        <ButtonGroup.Root aria-label="Symbol status filter">
          {#each [['all', 'All', 'cyan'], ['missing', 'Missing', 'red'], ['identical', 'Identical', 'green']] as const as [val, label, activeColor] (val)}
            <Button
              color={statusFilter === val ? activeColor : 'white'}
              size="sm"
              aria-pressed={statusFilter === val}
              onclick={() => {
                statusFilter = val;
                showAllRows = false;
              }}
            >
              {label}
            </Button>
          {/each}
        </ButtonGroup.Root>
      </div>
    </Card.Content>
  </Card.Root>

  {#if visibleRows.length > 0}
    <Table.Root headerColor="cyan" rowColor="white">
      <Table.Header>
        <Table.Row>
          <Table.Head>Address / ID</Table.Head>
          <Table.Head>Status</Table.Head>
          {#each snapshots as snap, idx (snap.id)}
            <Table.Head>
              <Badge color={getSnapshotPaletteEntry(idx).color}>{snap.label}</Badge>
            </Table.Head>
          {/each}
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each visibleRows as row (`${activeCategory}:${row.key}`)}
          <Table.Row>
            <Table.Cell class="font-mono text-xs whitespace-nowrap">{row.addressOrId}</Table.Cell>
            <Table.Cell class="font-mono text-xs">
              {#if row.status === 'identical'}
                <Badge color="green">identical</Badge>
              {:else if row.status === 'missing'}
                <Badge color="red">missing</Badge>
              {:else}
                <span>—</span>
              {/if}
            </Table.Cell>
            {#each row.items as item, idx (snapshots[idx]?.id ?? idx)}
              <Table.Cell class="max-w-md font-mono text-xs break-all">
                {#if item}
                  <div class="font-bold">{item.primaryName}</div>
                  <div>{item.secondaryType} · {item.meta}</div>
                {:else}
                  <span>-</span>
                {/if}
              </Table.Cell>
            {/each}
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>

    {#if !showAllRows && filteredRows.length > 200}
      <Button color="blue" size="sm" onclick={() => (showAllRows = true)}>
        Show all {filteredRows.length} rows
      </Button>
    {/if}
  {:else}
    <Alert.Root color="blue">
      <Alert.Title>No matching {activeCategory}</Alert.Title>
      <Alert.Description>No symbols match the current filter across loaded snapshots.</Alert.Description>
    </Alert.Root>
  {/if}
</div>
