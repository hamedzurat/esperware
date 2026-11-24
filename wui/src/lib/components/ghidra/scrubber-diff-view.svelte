<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import { Slider } from '#lib/components/ui/slider/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import { SHIKI_CONFIG, type GhidraClient, type RangeDiffResponse } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    maxVersion,
    selectedVersion,
    diffFnFilter,
    rangeFrom,
    rangeTo,
    formatVersionLabel,
    onRangeChange,
  }: {
    client: GhidraClient;
    maxVersion: number;
    selectedVersion: number;
    diffFnFilter: string;
    rangeFrom: number;
    rangeTo: number;
    formatVersionLabel: (v: number) => string;
    onRangeChange: (from: number, to: number) => void;
  } = $props();

  let rangeDiff = $state<RangeDiffResponse | null>(null);
  let rangeDiffLoading = $state(false);
  let rangeDiffError = $state<string | null>(null);

  let diffCtrl: AbortController | null = null;
  let diffReqSeq = 0;
  let diffDebounceTimer: ReturnType<typeof setTimeout> | undefined;
  let lastDispatchedKey = '';
  let isDragging = false;

  async function loadRangeDiff(from: number, to: number, fnFilter: string) {
    diffCtrl?.abort();
    const ctrl = new AbortController();
    diffCtrl = ctrl;

    const req = ++diffReqSeq;
    rangeDiffLoading = true;
    rangeDiffError = null;
    try {
      const target = fnFilter === '__all__' ? undefined : fnFilter;
      const res = await client.diff(from, to, target, ctrl.signal);
      if (req !== diffReqSeq || ctrl.signal.aborted) return;
      rangeDiff = res;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === diffReqSeq) {
        rangeDiffError = error instanceof Error ? error.message : 'Failed to load diff range.';
      }
    } finally {
      if (req === diffReqSeq) {
        rangeDiffLoading = false;
      }
    }
  }

  function scheduleRangeDiff(from: number, to: number, fnFilter: string, immediate = false) {
    if (diffDebounceTimer) {
      clearTimeout(diffDebounceTimer);
      diffDebounceTimer = undefined;
    }
    lastDispatchedKey = `${from}:${to}:${fnFilter}`;
    if (immediate) {
      isDragging = false;
      void loadRangeDiff(from, to, fnFilter);
      return;
    }
    isDragging = true;
    diffDebounceTimer = setTimeout(() => {
      isDragging = false;
      void loadRangeDiff(from, to, fnFilter);
    }, 120);
  }

  function handleRangeDrag(values: number[]) {
    if (values.length < 2) return;
    const nextFrom = Math.min(values[0], values[1]);
    const nextTo = Math.max(values[0], values[1]);
    onRangeChange(nextFrom, nextTo);
    scheduleRangeDiff(nextFrom, nextTo, diffFnFilter, false);
  }

  function handleRangeCommit(values: number[]) {
    if (values.length < 2) return;
    const nextFrom = Math.min(values[0], values[1]);
    const nextTo = Math.max(values[0], values[1]);
    onRangeChange(nextFrom, nextTo);
    scheduleRangeDiff(nextFrom, nextTo, diffFnFilter, true);
  }

  function applyRangePreset(from: number, to: number) {
    const clampedFrom = Math.max(0, Math.min(maxVersion, from));
    const clampedTo = Math.max(clampedFrom, Math.min(maxVersion, to));
    onRangeChange(clampedFrom, clampedTo);
    scheduleRangeDiff(clampedFrom, clampedTo, diffFnFilter, true);
  }

  $effect(() => {
    const from = rangeFrom;
    const to = rangeTo;
    const fnFilter = diffFnFilter;
    const ver = maxVersion;
    void ver;
    untrack(() => {
      const key = `${from}:${to}:${fnFilter}`;
      if (key !== lastDispatchedKey && !isDragging) {
        scheduleRangeDiff(from, to, fnFilter, true);
      }
    });
  });

  $effect(() => {
    return () => {
      if (diffDebounceTimer) {
        clearTimeout(diffDebounceTimer);
        diffDebounceTimer = undefined;
      }
      diffCtrl?.abort();
    };
  });
</script>

{#if rangeDiffError}
  <Alert.Root color="red">
    <Alert.Title>Diff range failed</Alert.Title>
    <Alert.Description>{rangeDiffError}</Alert.Description>
  </Alert.Root>
{/if}

{#if rangeDiffLoading && !rangeDiff}
  <Card.Root color="white">
    <Card.Content class="flex items-center gap-3 py-8">
      <Spinner color="magenta" />
      <span class="font-mono text-sm">Computing cumulative diff...</span>
    </Card.Content>
  </Card.Root>
{:else if rangeDiff && rangeDiff.diffs.length > 0}
  <div class="space-y-4">
    {#each rangeDiff.diffs as diff (diff.function_address)}
      <CodeBlock
        color="yellow"
        headerColor="magenta"
        lang="diff"
        title={`${diff.function_name} (${diff.function_address}) · v${rangeDiff.from} → v${rangeDiff.to}`}
        code={diff.diff || '(no pseudocode changes)'}
        shiki={SHIKI_CONFIG}
        copy
        download={`${diff.function_name}-v${rangeDiff.from}-v${rangeDiff.to}.diff`}
      />
    {/each}
  </div>
{:else}
  <Alert.Root color="blue">
    <Alert.Title>No differences between v{rangeFrom} and v{rangeTo}</Alert.Title>
    <Alert.Description>Drag the range thumbs below or pick another preset.</Alert.Description>
  </Alert.Root>
{/if}

<Card.Root color="white">
  <Card.Content class="space-y-4">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
        <Badge color="magenta">v{rangeFrom} → v{rangeTo}</Badge>
        {#if rangeDiffLoading}
          <Spinner color="magenta" />
        {/if}
      </div>

      <div class="flex flex-wrap items-center gap-1.5">
        <Button
          color="blue"
          size="sm"
          disabled={maxVersion <= 0}
          onclick={() => applyRangePreset(Math.max(0, maxVersion - 1), maxVersion)}
        >
          Prev → Latest
        </Button>
        <Button color="yellow" size="sm" disabled={maxVersion <= 0} onclick={() => applyRangePreset(0, maxVersion)}>
          v0 → Latest
        </Button>
        <Button
          color="cyan"
          size="sm"
          disabled={selectedVersion <= 0}
          onclick={() => applyRangePreset(Math.max(0, selectedVersion - 1), selectedVersion)}
        >
          Step v{selectedVersion}
        </Button>
      </div>
    </div>

    <div class="py-1">
      <Slider
        color="magenta"
        min={0}
        max={Math.max(1, maxVersion)}
        step={1}
        disabled={maxVersion <= 0}
        value={[rangeFrom, rangeTo]}
        aria-label="Scrub diff version range"
        onValueChange={handleRangeDrag}
        onValueCommit={handleRangeCommit}
      >
        {#snippet children(hoverVer)}
          <span>{formatVersionLabel(hoverVer)}</span>
        {/snippet}
      </Slider>
    </div>
  </Card.Content>
</Card.Root>
