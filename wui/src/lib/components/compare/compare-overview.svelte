<script lang="ts">
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Chart from '#lib/components/ui/chart/index.js';
  import { formatBytes } from '#lib/ghidra-api.ts';
  import {
    countSnapshotStats,
    getSnapshotPaletteEntry,
    type FunctionCompareRow,
    type FunctionFilter,
    type LoadedSnapshot,
  } from '#lib/snapshot-compare.ts';
  import { neoretroColors } from '#lib/utils.ts';
  import { BarChart, PieChart } from 'layerchart';

  let {
    snapshots,
    baselineIndex,
    functionRows,
    onJumpToFunctions,
  }: {
    snapshots: LoadedSnapshot[];
    baselineIndex: number;
    functionRows: FunctionCompareRow[];
    onJumpToFunctions: (filter: FunctionFilter, offset?: string) => void;
  } = $props();

  let sizeMetric = $state<'size' | 'lines'>('size');

  const safeBaselineIndex = $derived(baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0);
  const snapshotStats = $derived(snapshots.map((s) => countSnapshotStats(s)));
  const baselineStats = $derived(snapshotStats[safeBaselineIndex] ?? snapshotStats[0]);

  const seriesChartConfig = $derived.by(() => {
    const cfg: Chart.ChartConfig = {};
    snapshots.forEach((snap, idx) => {
      cfg[`s${idx}`] = {
        label: snap.label,
        color: getSnapshotPaletteEntry(idx).cssVar,
      };
    });
    return cfg;
  });

  const barSeries = $derived(
    snapshots.map((snap, idx) => ({
      key: `s${idx}`,
      label: snap.label,
      color: getSnapshotPaletteEntry(idx).cssVar,
    })),
  );

  const artifactRows = $derived.by(() => {
    const metrics = [
      { key: 'functions', label: 'Funcs' },
      { key: 'decompiled', label: 'Decomp' },
      { key: 'types', label: 'Types' },
      { key: 'globals', label: 'Globals' },
      { key: 'strings', label: 'Strings' },
      { key: 'edges', label: 'Edges' },
    ] as const;

    return metrics.map((m) => {
      const row: Record<string, string | number> = { metric: m.label };
      snapshotStats.forEach((st, idx) => {
        row[`s${idx}`] = st[m.key];
      });
      return row;
    });
  });

  const breakdownCounts = $derived.by(() => {
    let identical = 0;
    let sharedOnly = 0;
    let missing = 0;
    for (const r of functionRows) {
      if (r.status === 'identical') identical++;
      else if (r.status === 'missing') missing++;
      else sharedOnly++;
    }
    return { identical, sharedOnly, sharedTotal: identical + sharedOnly, missing };
  });

  const pieConfig: Chart.ChartConfig = {
    shared: { label: 'Shared', color: neoretroColors.cyan },
    identical: { label: 'Identical', color: neoretroColors.green },
    missing: { label: 'Missing', color: neoretroColors.red },
  };

  const pieData = $derived(
    [
      { key: 'shared' as const, label: 'Shared', value: breakdownCounts.sharedOnly, color: neoretroColors.cyan },
      { key: 'identical' as const, label: 'Identical', value: breakdownCounts.identical, color: neoretroColors.green },
      { key: 'missing' as const, label: 'Missing', value: breakdownCounts.missing, color: neoretroColors.red },
    ].filter((slice) => slice.value > 0),
  );

  const hasBundledLineCounts = $derived(functionRows.some((r) => r.lineCounts.some((c) => c !== null)));

  const effectiveSizeMetric = $derived(sizeMetric === 'lines' && hasBundledLineCounts ? 'lines' : 'size');

  const topFunctionRows = $derived.by(() => {
    const priority = (r: FunctionCompareRow) => (r.status === 'missing' ? 2 : r.status === 'identical' ? 0 : 1);
    const ranked = [...functionRows]
      .sort((a, b) => {
        const pd = priority(b) - priority(a);
        if (pd !== 0) return pd;
        return b.maxSize - a.maxSize;
      })
      .slice(0, 10);

    return ranked.map((r) => {
      const row: Record<string, string | number> = {
        key: r.key,
        label: `@${r.key}`,
        detail: `@${r.key} · ${r.displayName}`,
      };
      r.entries.forEach((fn, idx) => {
        row[`s${idx}`] = effectiveSizeMetric === 'lines' ? (r.lineCounts[idx] ?? 0) : (fn?.size ?? 0);
      });
      return row;
    });
  });

  function deltaText(current: number, base: number, isBase: boolean): string | null {
    if (isBase) return null;
    const diff = current - base;
    if (diff === 0) return null;
    return diff > 0 ? `+${diff}` : String(diff);
  }
</script>

<div class="space-y-4">
  <div
    class={snapshots.length >= 3
      ? 'grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3'
      : 'grid grid-cols-1 gap-4 md:grid-cols-2'}
  >
    {#each snapshots as snap, idx (snap.id)}
      {@const palette = getSnapshotPaletteEntry(idx)}
      {@const stats = snapshotStats[idx]}
      {@const isBase = idx === safeBaselineIndex}
      <Card.Root color="bright-black" class="min-w-0">
        <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2">
          <div class="flex min-w-0 flex-wrap items-center gap-2">
            <Badge color={palette.color}>{snap.label}</Badge>
            {#if isBase}
              <Badge color="yellow">Baseline</Badge>
            {/if}
            <Card.Title class="truncate font-mono text-base">{snap.manifest.binary_name}</Card.Title>
          </div>
          <Badge color="white">v{snap.manifest.version ?? 0}</Badge>
        </Card.Header>

        <Card.Content class="space-y-3">
          <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            {#if snap.manifest.format}
              <Badge color="white">{snap.manifest.format}</Badge>
            {/if}
            {#if snap.manifest.language}
              <Badge color="white">{snap.manifest.language}</Badge>
            {/if}
            {#if snap.manifest.compiler}
              <Badge color="white">{snap.manifest.compiler}</Badge>
            {/if}
            {#if snap.manifest.binary_sha256}
              <Badge color="blue">sha:{snap.manifest.binary_sha256.slice(0, 10)}</Badge>
            {/if}
            <Badge color="white">{snap.manifest.segments?.length ?? 0} segs</Badge>
          </div>

          <div class="grid grid-cols-3 gap-2 font-mono text-xs">
            {#each [['Funcs', stats.functions, baselineStats.functions], ['Decomp', stats.decompiled, baselineStats.decompiled], ['Types', stats.types, baselineStats.types], ['Globals', stats.globals, baselineStats.globals], ['Strings', stats.strings, baselineStats.strings], ['Edges', stats.edges, baselineStats.edges]] as const as [name, val, baseVal] (name)}
              {@const delta = deltaText(val, baseVal, isBase)}
              <div class="neoretro-border rounded px-2 py-1.5" data-color="white">
                <div class="flex items-center justify-between gap-1">
                  <span>{name}</span>
                  {#if delta}
                    <Badge color={val > baseVal ? 'green' : 'red'}>{delta}</Badge>
                  {/if}
                </div>
                <div class="text-sm font-bold">{val}</div>
              </div>
            {/each}
          </div>
        </Card.Content>
      </Card.Root>
    {/each}
  </div>

  <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
    <Card.Root color="white" class="min-w-0">
      <Card.Header>
        <Card.Title class="font-mono text-sm">Artifact Counts</Card.Title>
      </Card.Header>
      <Card.Content class="min-w-0">
        <Chart.Container config={seriesChartConfig} class="aspect-auto h-64 w-full min-w-0">
          <BarChart
            data={artifactRows}
            x="metric"
            series={barSeries}
            seriesLayout="group"
            padding={{ top: 12, right: 12, bottom: 28, left: 36 }}
          >
            {#snippet tooltip()}
              <Chart.Tooltip color="white" dataLabelKey="metric" />
            {/snippet}
          </BarChart>
        </Chart.Container>
      </Card.Content>
    </Card.Root>

    <Card.Root color="white" class="min-w-0">
      <Card.Header class="flex flex-row items-center justify-between gap-2">
        <Card.Title class="font-mono text-sm">Function Coverage ({functionRows.length})</Card.Title>
        <Badge color="cyan">{breakdownCounts.sharedTotal}/{functionRows.length} shared</Badge>
      </Card.Header>
      <Card.Content class="min-w-0 space-y-3">
        {#if pieData.length > 0}
          <Chart.Container config={pieConfig} class="aspect-auto h-52 w-full min-w-0">
            <PieChart
              data={pieData}
              key="key"
              label="label"
              value="value"
              c="color"
              innerRadius={-24}
              padAngle={0.03}
              cornerRadius={3}
              onArcClick={(_e, detail) => {
                const sliceKey = (detail.data as { key?: FunctionFilter } | undefined)?.key;
                if (sliceKey) onJumpToFunctions(sliceKey);
              }}
            >
              {#snippet tooltip()}
                <Chart.Tooltip color="white" hideLabel />
              {/snippet}
            </PieChart>
          </Chart.Container>
        {:else}
          <p class="py-12 text-center font-mono text-xs">No functions in loaded snapshots.</p>
        {/if}

        <div class="flex flex-wrap items-center justify-center gap-2">
          <Button color="cyan" size="sm" onclick={() => onJumpToFunctions('shared')}>
            Shared ({breakdownCounts.sharedTotal})
          </Button>
          <Button color="red" size="sm" onclick={() => onJumpToFunctions('missing')}>
            Missing ({breakdownCounts.missing})
          </Button>
          <Button color="green" size="sm" onclick={() => onJumpToFunctions('identical')}>
            Identical ({breakdownCounts.identical})
          </Button>
        </div>
      </Card.Content>
    </Card.Root>

    <Card.Root color="white" class="min-w-0">
      <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2">
        <Card.Title class="font-mono text-sm">Top Functions (click bar to inspect)</Card.Title>
        <ButtonGroup.Root aria-label="Function size metric">
          <Button
            color={effectiveSizeMetric === 'size' ? 'cyan' : 'white'}
            size="sm"
            aria-pressed={effectiveSizeMetric === 'size'}
            onclick={() => (sizeMetric = 'size')}
          >
            Bytes
          </Button>
          <Button
            color={effectiveSizeMetric === 'lines' ? 'cyan' : 'white'}
            size="sm"
            disabled={!hasBundledLineCounts}
            aria-pressed={effectiveSizeMetric === 'lines'}
            onclick={() => (sizeMetric = 'lines')}
          >
            C Lines
          </Button>
        </ButtonGroup.Root>
      </Card.Header>
      <Card.Content class="min-w-0">
        {#if topFunctionRows.length > 0}
          <Chart.Container config={seriesChartConfig} class="aspect-auto h-64 w-full min-w-0">
            <BarChart
              data={topFunctionRows}
              x="label"
              series={barSeries}
              seriesLayout="group"
              padding={{ top: 12, right: 12, bottom: 28, left: 40 }}
              onBarClick={(_e, detail) => {
                const offsetKey = (detail.data as { key?: string } | undefined)?.key;
                if (offsetKey) onJumpToFunctions('all', offsetKey);
              }}
            >
              {#snippet tooltip()}
                <Chart.Tooltip color="white" dataLabelKey="detail" />
              {/snippet}
            </BarChart>
          </Chart.Container>
        {:else}
          <p class="py-12 text-center font-mono text-xs">
            No function size data ({formatBytes(0)}).
          </p>
        {/if}
      </Card.Content>
    </Card.Root>
  </div>
</div>
