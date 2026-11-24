<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import { SHIKI_CONFIG } from '#lib/ghidra-api.ts';
  import { computeUnifiedDiff, getSnapshotPaletteEntry, type LoadedSnapshot } from '#lib/snapshot-compare.ts';

  let {
    snapshots,
    baselineIndex,
  }: {
    snapshots: LoadedSnapshot[];
    baselineIndex: number;
  } = $props();

  let viewMode = $state<'diff' | 'side-by-side'>('diff');

  const safeBaselineIndex = $derived(baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0);
  const baseSnap = $derived(snapshots[safeBaselineIndex]);

  const diffEntries = $derived.by(() =>
    snapshots
      .map((snap, idx) => ({ snap, idx }))
      .filter(({ idx }) => idx !== safeBaselineIndex)
      .map(({ snap, idx }) => ({
        snap,
        idx,
        result: computeUnifiedDiff(baseSnap.label, snap.label, baseSnap.typesHeader, snap.typesHeader),
      })),
  );

  const sideGridClass = $derived(
    snapshots.length >= 3
      ? 'grid grid-cols-1 gap-4 xl:grid-cols-2 2xl:grid-cols-3'
      : 'grid grid-cols-1 gap-4 xl:grid-cols-2',
  );
</script>

<div class="space-y-4">
  <Card.Root color="bright-black" class="min-w-0">
    <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <Card.Title class="font-mono text-base">types.h Comparison</Card.Title>
        {#each snapshots as snap, idx (snap.id)}
          {@const lineCount = snap.typesHeader ? snap.typesHeader.split(/\r?\n/).length : 0}
          <Badge color={getSnapshotPaletteEntry(idx).color}>
            {snap.label}: {lineCount}L
          </Badge>
        {/each}
      </div>

      <ButtonGroup.Root aria-label="Types comparison view">
        <Button
          color={viewMode === 'diff' ? 'yellow' : 'white'}
          size="sm"
          aria-pressed={viewMode === 'diff'}
          onclick={() => (viewMode = 'diff')}
        >
          Diff vs {baseSnap.label}
        </Button>
        <Button
          color={viewMode === 'side-by-side' ? 'cyan' : 'white'}
          size="sm"
          aria-pressed={viewMode === 'side-by-side'}
          onclick={() => (viewMode = 'side-by-side')}
        >
          Side-by-side types.h
        </Button>
      </ButtonGroup.Root>
    </Card.Header>
  </Card.Root>

  {#if viewMode === 'diff'}
    <div class="space-y-4">
      {#each diffEntries as item (item.snap.id)}
        {@const palette = getSnapshotPaletteEntry(item.idx)}
        {#if item.result.identical}
          <Alert.Root color="green">
            <Alert.Title>{baseSnap.label} → {item.snap.label}</Alert.Title>
            <Alert.Description><code>types.h</code> is identical.</Alert.Description>
          </Alert.Root>
        {:else}
          <CodeBlock
            color="yellow"
            headerColor={palette.color}
            lang="diff"
            title={`${baseSnap.label} → ${item.snap.label} · types.h (+${item.result.added} / -${item.result.removed})`}
            code={item.result.diff}
            shiki={SHIKI_CONFIG}
            lines={36}
            copy
          />
        {/if}
      {/each}
    </div>
  {:else}
    <div class={sideGridClass}>
      {#each snapshots as snap, idx (snap.id)}
        {@const palette = getSnapshotPaletteEntry(idx)}
        <Card.Root color="white" class="min-w-0">
          <Card.Content class="pt-4">
            <CodeBlock
              color="white"
              headerColor={palette.color}
              lang="c"
              title={`${snap.label} · types.h`}
              code={snap.typesHeader || '/* types.h missing */'}
              shiki={SHIKI_CONFIG}
              lines={36}
              copy
            />
          </Card.Content>
        </Card.Root>
      {/each}
    </div>
  {/if}
</div>
