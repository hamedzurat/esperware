<script lang="ts">
  import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
  import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
  import CodeIcon from '@lucide/svelte/icons/code';
  import GitCompareIcon from '@lucide/svelte/icons/git-compare';
  import HistoryIcon from '@lucide/svelte/icons/history';
  import SearchCodeIcon from '@lucide/svelte/icons/search-code';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { getKeyedVariant, setKeyedVariant } from '#lib/components/ui/code-block/code-block-store.svelte.ts';
  import { CodeBlock, type CodeBlockVariant } from '#lib/components/ui/code-block/index.js';
  import * as Collapsible from '#lib/components/ui/collapsible/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import * as Select from '#lib/components/ui/select/index.js';
  import { Slider } from '#lib/components/ui/slider/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import {
    buildFunctionTimeline,
    collectTouchedFunctions,
    isExternalSegmentAddress,
    sameAddress,
    SHIKI_CONFIG,
    type FunctionRow,
    type GhidraClient,
    type RangeDiffResponse,
    type SegmentInfo,
    type UrlNavState,
    type VersionDetail,
    type VersionSummary,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';

  let {
    client,
    versions,
    currentVersion,
    segments = [],
    active = true,
    versionCache,
    ensureVersionDetail,
    focusRequest = null,
    initialNav = undefined,
    onInspectFunction,
    onNavChange = undefined,
  }: {
    client: GhidraClient;
    versions: VersionSummary[];
    currentVersion: number;
    segments?: SegmentInfo[];
    active?: boolean;
    versionCache: SvelteMap<number, VersionDetail>;
    ensureVersionDetail: (version: number) => Promise<VersionDetail | null>;
    focusRequest?: { addr: string; seq: number } | null;
    initialNav?: UrlNavState;
    onInspectFunction: (target: string) => void;
    onNavChange?: (patch: Partial<UrlNavState>) => void;
  } = $props();

  const variantKey = $derived(`esperware-scrub-${client.baseUrl}`);

  let sidebarTab = $state<'versions' | 'functions'>('versions');
  let scrubMode = $state<'snapshot' | 'diff'>(untrack(() => initialNav?.scrubMode ?? 'snapshot'));
  let selectedVersion = $state(untrack(() => initialNav?.scrubVersion ?? 0));
  let scrubVersion = $state(untrack(() => initialNav?.scrubVersion ?? 0));
  let rangeFrom = $state(untrack(() => initialNav?.diffFrom ?? 0));
  let rangeTo = $state(untrack(() => initialNav?.diffTo ?? 0));
  let selectedFnAddr = $state(untrack(() => initialNav?.scrubFn ?? ''));
  let diffFnFilter = $state(untrack(() => initialNav?.scrubFn || '__all__'));
  let opsOpen = $state(false);

  let fallbackFunctions = $state<FunctionRow[]>([]);
  let fallbackCodeMap = new SvelteMap<string, { name: string; code: string }>();
  let loadingTimeline = $state(false);
  let timelineError = $state<string | null>(null);

  let rangeDiff = $state<RangeDiffResponse | null>(null);
  let rangeDiffLoading = $state(false);
  let rangeDiffError = $state<string | null>(null);

  let lastKnownMax = -1;
  let lastFocusSeq = 0;
  let timelineReqSeq = 0;
  let diffReqSeq = 0;
  let diffDebounceTimer: ReturnType<typeof setTimeout> | undefined;

  const maxVersion = $derived(versions.length ? versions[versions.length - 1].version : currentVersion);
  const versionsDesc = $derived([...versions].reverse());
  const versionMap = $derived(new Map(versions.map((v) => [v.version, v])));
  const touchedFunctions = $derived(collectTouchedFunctions(versions));

  const selectableFunctions = $derived(
    touchedFunctions.length > 0
      ? touchedFunctions.map((fn) => ({
          address: fn.address,
          name: fn.name,
          subtitle: `${fn.versions.length} edit${fn.versions.length === 1 ? '' : 's'} · v${fn.latestVersion}`,
        }))
      : fallbackFunctions.map((fn) => ({
          address: fn.address,
          name: fn.name,
          subtitle: `${fn.size} B`,
        })),
  );

  const selectedFnEntry = $derived(
    selectableFunctions.find(
      (fn) => sameAddress(fn.address, selectedFnAddr) || fn.name.toLowerCase() === selectedFnAddr.trim().toLowerCase(),
    ) ??
      selectableFunctions[0] ??
      null,
  );

  const activeFnAddr = $derived(selectedFnEntry?.address ?? selectedFnAddr);
  const fallbackEntry = $derived(
    activeFnAddr
      ? Array.from(fallbackCodeMap.entries()).find(([addr]) => sameAddress(addr, activeFnAddr))?.[1]
      : undefined,
  );

  const timelineSteps = $derived(
    activeFnAddr ? buildFunctionTimeline(activeFnAddr, versions, versionCache, fallbackEntry?.code) : [],
  );

  const codeVariants = $derived<CodeBlockVariant[]>(
    timelineSteps.map((step) => ({
      value: `v${step.version}`,
      label: step.changed ? `v${step.version} *` : `v${step.version}`,
      code: step.code,
    })),
  );

  const activeStep = $derived(
    timelineSteps.find((step) => step.version === scrubVersion) ?? timelineSteps[timelineSteps.length - 1] ?? null,
  );

  const changedVersions = $derived(timelineSteps.filter((step) => step.changed).map((step) => step.version));

  const prevChangedVersion = $derived.by(() => {
    for (let i = changedVersions.length - 1; i >= 0; i--) {
      if (changedVersions[i] < scrubVersion) return changedVersions[i];
    }
    return null;
  });

  const nextChangedVersion = $derived.by(() => {
    for (const v of changedVersions) {
      if (v > scrubVersion) return v;
    }
    return null;
  });

  const activeVersionSummary = $derived(versionMap.get(selectedVersion) ?? null);
  const activeVersionDetail = $derived(versionCache.get(selectedVersion) ?? null);

  function setScrubVersion(next: number) {
    const clamped = Math.max(0, Math.min(maxVersion, next));
    scrubVersion = clamped;
    selectedVersion = clamped;
    setKeyedVariant(`v${clamped}`, variantKey);
  }

  function formatVersionLabel(v: number): string {
    const meta = versionMap.get(v);
    if (!meta) return `v${v}`;
    const parts = [`v${v}`, meta.operation];
    if (meta.checkpoint_label) parts.push(`[${meta.checkpoint_label}]`);
    if (meta.reason) parts.push(meta.reason);
    return parts.join(' · ');
  }

  async function prefetchFunctionHistory(addr: string) {
    const req = ++timelineReqSeq;
    timelineError = null;
    const relevant = versions
      .filter((v) => v.functions.some((f) => sameAddress(f.function_address, addr)))
      .map((v) => v.version);

    const missing = relevant.filter((v) => !versionCache.has(v));
    const hasFallback = Array.from(fallbackCodeMap.keys()).some((k) => sameAddress(k, addr));
    if (missing.length === 0 && (relevant.length > 0 || hasFallback)) {
      return;
    }
    loadingTimeline = true;
    try {
      if (missing.length > 0) {
        await Promise.all(missing.map((v) => ensureVersionDetail(v)));
        if (req !== timelineReqSeq) return;
      }
      if (relevant.length === 0 && !hasFallback) {
        const detail = await client.functionDetail(addr);
        if (req !== timelineReqSeq) return;
        fallbackCodeMap.set(detail.function.address.toLowerCase(), {
          name: detail.function.name,
          code: detail.pseudocode || detail.decompile_error || '/* empty */',
        });
      }
    } catch (error) {
      if (req === timelineReqSeq) {
        timelineError = error instanceof Error ? error.message : 'Failed to load version history.';
      }
    } finally {
      if (req === timelineReqSeq) {
        loadingTimeline = false;
      }
    }
  }

  async function loadRangeDiff(from: number, to: number, fnFilter: string) {
    const req = ++diffReqSeq;
    rangeDiffLoading = true;
    rangeDiffError = null;
    try {
      const target = fnFilter === '__all__' ? undefined : fnFilter;
      const res = await client.diff(from, to, target);
      if (req !== diffReqSeq) return;
      rangeDiff = res;
    } catch (error) {
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
    if (immediate) {
      void loadRangeDiff(from, to, fnFilter);
      return;
    }
    diffDebounceTimer = setTimeout(() => {
      void loadRangeDiff(from, to, fnFilter);
    }, 120);
  }

  function handleRangeDrag(values: number[]) {
    if (values.length < 2) return;
    const nextFrom = Math.min(values[0], values[1]);
    const nextTo = Math.max(values[0], values[1]);
    rangeFrom = nextFrom;
    rangeTo = nextTo;
    selectedVersion = nextTo;
    scheduleRangeDiff(nextFrom, nextTo, diffFnFilter, false);
  }

  function handleRangeCommit(values: number[]) {
    if (values.length < 2) return;
    const nextFrom = Math.min(values[0], values[1]);
    const nextTo = Math.max(values[0], values[1]);
    rangeFrom = nextFrom;
    rangeTo = nextTo;
    selectedVersion = nextTo;
    scheduleRangeDiff(nextFrom, nextTo, diffFnFilter, true);
  }

  function applyRangePreset(from: number, to: number) {
    const clampedFrom = Math.max(0, Math.min(maxVersion, from));
    const clampedTo = Math.max(clampedFrom, Math.min(maxVersion, to));
    rangeFrom = clampedFrom;
    rangeTo = clampedTo;
    selectedVersion = clampedTo;
    scheduleRangeDiff(clampedFrom, clampedTo, diffFnFilter, true);
  }

  function handleSidebarVersionClick(v: VersionSummary) {
    selectedVersion = v.version;
    if (scrubMode === 'snapshot') {
      const touchesCurrent = v.functions.some((f) => sameAddress(f.function_address, activeFnAddr));
      if (!touchesCurrent && v.functions.length > 0) {
        selectedFnAddr = v.functions[0].function_address;
        diffFnFilter = v.functions[0].function_address;
      }
      setScrubVersion(v.version);
    } else {
      applyRangePreset(Math.max(0, v.version - 1), v.version);
    }
  }

  function handleSidebarFnClick(address: string) {
    selectedFnAddr = address;
    diffFnFilter = address;
    if (scrubMode === 'diff') {
      scheduleRangeDiff(rangeFrom, rangeTo, address, true);
    }
  }

  function switchScrubMode(nextMode: 'snapshot' | 'diff') {
    scrubMode = nextMode;
    if (nextMode === 'snapshot') {
      if (diffDebounceTimer) {
        clearTimeout(diffDebounceTimer);
        diffDebounceTimer = undefined;
      }
      return;
    }
    if (nextMode === 'diff') {
      if (rangeTo === 0 && maxVersion > 0) {
        rangeFrom = Math.max(0, maxVersion - 1);
        rangeTo = maxVersion;
      }
      scheduleRangeDiff(rangeFrom, rangeTo, diffFnFilter, true);
    }
  }

  $effect(() => {
    return () => {
      if (diffDebounceTimer) {
        clearTimeout(diffDebounceTimer);
        diffDebounceTimer = undefined;
      }
    };
  });

  // Keep version state synced when live SSE versions arrive.
  $effect(() => {
    const nextMax = maxVersion;
    const prevMax = lastKnownMax;
    if (prevMax === -1) {
      lastKnownMax = nextMax;
      untrack(() => {
        const initVer = initialNav?.scrubVersion !== undefined ? initialNav.scrubVersion : nextMax;
        setScrubVersion(initVer);
        const initTo = initialNav?.diffTo !== undefined ? Math.max(0, Math.min(nextMax, initialNav.diffTo)) : nextMax;
        const initFrom =
          initialNav?.diffFrom !== undefined
            ? Math.max(0, Math.min(initTo, initialNav.diffFrom))
            : Math.max(0, nextMax - 1);
        rangeFrom = initFrom;
        rangeTo = initTo;
        if (scrubMode === 'diff') {
          selectedVersion = initTo;
          scheduleRangeDiff(initFrom, initTo, diffFnFilter, true);
        }
      });
      return;
    }
    if (nextMax !== prevMax) {
      lastKnownMax = nextMax;
      untrack(() => {
        if (scrubVersion === prevMax) {
          setScrubVersion(nextMax);
        }
        if (rangeTo === prevMax) {
          rangeTo = nextMax;
          if (scrubMode === 'diff') scheduleRangeDiff(rangeFrom, nextMax, diffFnFilter, true);
        }
      });
    }
  });

  // Sync external focus requests (e.g. "Scrub versions" button in Functions tab).
  $effect(() => {
    if (!focusRequest || focusRequest.seq === lastFocusSeq) return;
    lastFocusSeq = focusRequest.seq;
    selectedFnAddr = focusRequest.addr;
    diffFnFilter = focusRequest.addr;
    scrubMode = 'snapshot';
  });

  // Load initial non-external functions when no edits exist yet so CodeBlock still has content to inspect.
  $effect(() => {
    const isActive = active;
    const hasTouched = touchedFunctions.length > 0;
    void currentVersion;
    if (!isActive || hasTouched) return;
    let cancelled = false;
    void (async () => {
      try {
        const res = await client.functions({ limit: 25 });
        if (cancelled) return;
        fallbackFunctions = res.functions.filter((f) => !f.external && !isExternalSegmentAddress(f.address, segments));
      } catch {
        // Primary error banner handles connection issues.
      }
    })();
    return () => {
      cancelled = true;
    };
  });

  // Ensure a valid function stays selected when lists load.
  $effect(() => {
    if (!selectableFunctions.length) return;
    if (!selectedFnAddr) {
      selectedFnAddr = selectableFunctions[0].address;
      return;
    }
    if (!untrack(() => initialNav?.scrubFn)) {
      const exists = selectableFunctions.some(
        (fn) =>
          sameAddress(fn.address, selectedFnAddr) || fn.name.toLowerCase() === selectedFnAddr.trim().toLowerCase(),
      );
      if (!exists) selectedFnAddr = selectableFunctions[0].address;
    }
  });

  // Prefetch version diffs whenever the selected function or version list changes.
  $effect(() => {
    if (!active) return;
    const addr = activeFnAddr;
    void versions.length;
    if (!addr) return;
    untrack(() => {
      void prefetchFunctionHistory(addr);
    });
  });

  // Ensure ops JSON is loaded for the currently selected version.
  $effect(() => {
    if (!active) return;
    const v = selectedVersion;
    if (!versionMap.has(v) || versionCache.has(v)) return;
    untrack(() => {
      void ensureVersionDetail(v);
    });
  });

  // Sync CodeBlock header dropdown selection back to the slider.
  $effect(() => {
    const kv = getKeyedVariant(variantKey);
    const match = /^v(\d+)$/.exec(kv);
    if (!match) return;
    const parsed = Number.parseInt(match[1], 10);
    if (parsed >= 0 && parsed <= maxVersion && parsed !== scrubVersion) {
      scrubVersion = parsed;
      selectedVersion = parsed;
    }
  });

  // Report scrubber navigation changes back to the parent URL state.
  $effect(() => {
    const mode = scrubMode;
    const fn = mode === 'diff' ? (diffFnFilter === '__all__' ? '' : diffFnFilter) : activeFnAddr;
    const v = scrubVersion;
    const from = rangeFrom;
    const to = rangeTo;
    untrack(() => {
      onNavChange?.({ scrubMode: mode, scrubFn: fn, scrubVersion: v, diffFrom: from, diffTo: to });
    });
  });
</script>

<div class="grid grid-cols-1 items-start gap-4 lg:grid-cols-[310px_1fr]">
  <Card.Root color="bright-black" class="min-w-0">
    <Card.Header>
      <Card.Title class="flex items-center justify-between gap-2 text-lg">
        <span>Timeline</span>
        <Badge color="yellow">{versions.length} ver</Badge>
      </Card.Title>
      <ButtonGroup.Root class="w-full" aria-label="Timeline view">
        <Button
          color={sidebarTab === 'versions' ? 'cyan' : 'white'}
          size="sm"
          class="flex-1"
          onclick={() => (sidebarTab = 'versions')}
        >
          <HistoryIcon />
          Versions
        </Button>
        <Button
          color={sidebarTab === 'functions' ? 'cyan' : 'white'}
          size="sm"
          class="flex-1"
          onclick={() => (sidebarTab = 'functions')}
        >
          <CodeIcon />
          Changed ({touchedFunctions.length})
        </Button>
      </ButtonGroup.Root>
    </Card.Header>

    <Card.Content>
      <div class="space-y-2 p-1">
        {#if sidebarTab === 'versions'}
          {#each versionsDesc as v (v.version)}
            {@const isSelected = selectedVersion === v.version}
            <Item.Root
              color={isSelected ? 'cyan' : 'white'}
              size="sm"
              pressable
              class="mb-0 w-full cursor-pointer text-left"
            >
              {#snippet child({ props })}
                <button {...props} type="button" onclick={() => handleSidebarVersionClick(v)}>
                  <Item.Content>
                    <Item.Header>
                      <Item.Title class="font-mono">
                        <span>v{v.version}</span>
                        <span>·</span>
                        <span>{v.operation}</span>
                      </Item.Title>
                      {#if v.checkpoint_label}
                        <Badge color="yellow">{v.checkpoint_label}</Badge>
                      {/if}
                    </Item.Header>
                    <Item.Description>
                      {v.reason || 'baseline'}
                    </Item.Description>
                    <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                      <Badge color="bright-black">{v.ops_count} ops</Badge>
                      <Badge color="bright-black">{v.functions.length} fns</Badge>
                      <span>{v.actor}</span>
                    </div>
                  </Item.Content>
                </button>
              {/snippet}
            </Item.Root>
          {/each}
        {:else if touchedFunctions.length === 0}
          <Alert.Root color="blue">
            <Alert.Title>No function edits yet</Alert.Title>
            <Alert.Description>Edits applied via /mcp/rw will list changed functions here.</Alert.Description>
          </Alert.Root>
        {:else}
          {#each touchedFunctions as fn (fn.address)}
            {@const isSelected = sameAddress(activeFnAddr, fn.address)}
            <Item.Root
              color={isSelected ? 'cyan' : 'white'}
              size="sm"
              pressable
              class="mb-0 w-full cursor-pointer text-left"
            >
              {#snippet child({ props })}
                <button {...props} type="button" onclick={() => handleSidebarFnClick(fn.address)}>
                  <Item.Content>
                    <Item.Header>
                      <Item.Title class="truncate font-mono">{fn.name}</Item.Title>
                      <Badge color="yellow">v{fn.latestVersion}</Badge>
                    </Item.Header>
                    <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                      <span>@{fn.address}</span>
                      <span>·</span>
                      <span>{fn.versions.map((ver) => `v${ver}`).join(', ')}</span>
                    </div>
                  </Item.Content>
                </button>
              {/snippet}
            </Item.Root>
          {/each}
        {/if}
      </div>
    </Card.Content>
  </Card.Root>

  <div class="flex min-w-0 flex-col gap-4">
    <Card.Root color="bright-black">
      <Card.Content class="flex flex-wrap items-center justify-between gap-3">
        <ButtonGroup.Root aria-label="Scrubber mode">
          <Button
            color={scrubMode === 'snapshot' ? 'cyan' : 'white'}
            size="sm"
            onclick={() => switchScrubMode('snapshot')}
          >
            <CodeIcon />
            Snapshot Scrub
          </Button>
          <Button color={scrubMode === 'diff' ? 'magenta' : 'white'} size="sm" onclick={() => switchScrubMode('diff')}>
            <GitCompareIcon />
            Diff Range
          </Button>
        </ButtonGroup.Root>

        <div class="flex min-w-0 flex-1 flex-wrap items-center justify-end gap-2">
          {#if scrubMode === 'snapshot'}
            {#if selectableFunctions.length > 0}
              <div class="w-full min-w-52 sm:w-72">
                <Select.Root
                  type="single"
                  color="yellow"
                  value={activeFnAddr}
                  onValueChange={(value) => {
                    if (value) {
                      selectedFnAddr = value;
                      diffFnFilter = value;
                    }
                  }}
                >
                  <Select.Trigger aria-label="Select function to scrub">
                    <span class="truncate font-mono text-xs">
                      {selectedFnEntry ? `${selectedFnEntry.name} @ ${selectedFnEntry.address}` : 'Choose function'}
                    </span>
                  </Select.Trigger>
                  <Select.Content>
                    {#each selectableFunctions as fn (fn.address)}
                      <Select.Item value={fn.address} label={`${fn.name} @ ${fn.address} (${fn.subtitle})`} />
                    {/each}
                  </Select.Content>
                </Select.Root>
              </div>
            {/if}
          {:else}
            <div class="w-full min-w-52 sm:w-72">
              <Select.Root
                type="single"
                color="yellow"
                value={diffFnFilter}
                onValueChange={(value) => {
                  if (value) {
                    diffFnFilter = value;
                    scheduleRangeDiff(rangeFrom, rangeTo, value, true);
                  }
                }}
              >
                <Select.Trigger aria-label="Filter diff by function">
                  <span class="truncate font-mono text-xs">
                    {diffFnFilter === '__all__'
                      ? 'All changed functions'
                      : (selectableFunctions.find(
                          (f) =>
                            sameAddress(f.address, diffFnFilter) || f.name.toLowerCase() === diffFnFilter.toLowerCase(),
                        )?.name ?? diffFnFilter)}
                  </span>
                </Select.Trigger>
                <Select.Content>
                  <Select.Item value="__all__" label="All changed functions" />
                  {#each touchedFunctions as fn (fn.address)}
                    <Select.Item value={fn.address} label={`${fn.name} @ ${fn.address}`} />
                  {/each}
                </Select.Content>
              </Select.Root>
            </div>
          {/if}

          {#if activeFnAddr}
            <Button color="blue" size="sm" onclick={() => onInspectFunction(activeFnAddr)}>
              <SearchCodeIcon />
              Inspect
            </Button>
          {/if}
        </div>
      </Card.Content>
    </Card.Root>

    {#if scrubMode === 'snapshot'}
      {#if timelineError}
        <Alert.Root color="red">
          <Alert.Title>History load failed</Alert.Title>
          <Alert.Description>{timelineError}</Alert.Description>
        </Alert.Root>
      {/if}

      {#if loadingTimeline && codeVariants.length === 0}
        <Card.Root color="white">
          <Card.Content class="flex items-center gap-3 py-8">
            <Spinner color="blue" />
            <span class="font-mono text-sm">Loading version snapshots...</span>
          </Card.Content>
        </Card.Root>
      {:else if codeVariants.length > 0 && activeStep}
        <CodeBlock
          color="yellow"
          headerColor="blue"
          lang="c"
          title={`${activeStep.name} @ ${activeFnAddr} — v${activeStep.version}`}
          shiki={SHIKI_CONFIG}
          variants={codeVariants}
          {variantKey}
          numbered
          copy
          download={`${activeStep.name}-v${activeStep.version}.c`}
        />

        <Card.Root color="white">
          <Card.Content class="space-y-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
                <Badge color={activeStep.changed ? 'cyan' : 'bright-black'}>
                  v{activeStep.version} / v{maxVersion}
                </Badge>
                <Badge color="yellow">{activeStep.operation}</Badge>
                {#if activeStep.checkpointLabel}
                  <Badge color="green">{activeStep.checkpointLabel}</Badge>
                {/if}
                <span>{activeStep.reason || 'baseline'}</span>
              </div>

              <div class="flex flex-wrap items-center gap-1.5">
                <Button
                  color="blue"
                  size="icon-sm"
                  aria-label="Previous version"
                  disabled={scrubVersion <= 0}
                  onclick={() => setScrubVersion(scrubVersion - 1)}
                >
                  <ChevronLeftIcon />
                </Button>
                <Button
                  color="blue"
                  size="icon-sm"
                  aria-label="Next version"
                  disabled={scrubVersion >= maxVersion}
                  onclick={() => setScrubVersion(scrubVersion + 1)}
                >
                  <ChevronRightIcon />
                </Button>
                <Button
                  color="magenta"
                  size="sm"
                  disabled={prevChangedVersion === null}
                  onclick={() => prevChangedVersion !== null && setScrubVersion(prevChangedVersion)}
                >
                  Prev edit
                </Button>
                <Button
                  color="magenta"
                  size="sm"
                  disabled={nextChangedVersion === null}
                  onclick={() => nextChangedVersion !== null && setScrubVersion(nextChangedVersion)}
                >
                  Next edit
                </Button>
              </div>
            </div>

            <div class="py-1">
              <Slider
                color="cyan"
                min={0}
                max={Math.max(1, maxVersion)}
                step={1}
                disabled={maxVersion <= 0}
                value={[scrubVersion]}
                aria-label="Scrub function version"
                onValueChange={(vals) => {
                  if (vals.length > 0) setScrubVersion(vals[0]);
                }}
              >
                {#snippet children(hoverVer)}
                  <span>{formatVersionLabel(hoverVer)}</span>
                {/snippet}
              </Slider>
            </div>

            {#if changedVersions.length > 0}
              <div class="flex flex-wrap items-center gap-1.5">
                <span class="font-mono text-xs font-bold">Edited at:</span>
                {#each changedVersions as ver (ver)}
                  <Button
                    color={ver === scrubVersion ? 'cyan' : 'yellow'}
                    size="sm"
                    onclick={() => setScrubVersion(ver)}
                  >
                    v{ver}
                  </Button>
                {/each}
              </div>
            {/if}
          </Card.Content>
        </Card.Root>
      {:else}
        <Alert.Root color="blue">
          <Alert.Title>No pseudocode available yet</Alert.Title>
          <Alert.Description>
            Connect to a binary with functions or apply edits via MCP to scrub versions.
          </Alert.Description>
        </Alert.Root>
      {/if}
    {:else}
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
              <Button
                color="yellow"
                size="sm"
                disabled={maxVersion <= 0}
                onclick={() => applyRangePreset(0, maxVersion)}
              >
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
    {/if}

    <Card.Root color="bright-black">
      <Card.Content>
        <Collapsible.Root bind:open={opsOpen}>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
              <Badge color="cyan">v{selectedVersion}</Badge>
              <span>{activeVersionSummary?.operation ?? 'initial'}</span>
              <span>·</span>
              <span>{activeVersionSummary?.actor ?? 'system'}</span>
              {#if activeVersionSummary?.created_at}
                <span>·</span>
                <span>{activeVersionSummary.created_at}</span>
              {/if}
            </div>
            <Collapsible.Trigger>
              {#snippet child({ props })}
                <Button {...props} tabindex={0} color="yellow" size="sm">
                  {opsOpen ? 'Hide' : 'Show'} operations ({activeVersionSummary?.ops_count ?? 0})
                </Button>
              {/snippet}
            </Collapsible.Trigger>
          </div>

          <Collapsible.Content class="pt-3">
            {#if activeVersionDetail}
              <CodeBlock
                color="cyan"
                headerColor="blue"
                lang="json"
                title={`v${activeVersionDetail.version} operations`}
                code={JSON.stringify(activeVersionDetail.ops, null, 2)}
                shiki={SHIKI_CONFIG}
                copy
              />
            {:else}
              <div class="flex items-center gap-2 py-3 font-mono text-xs">
                <Spinner color="yellow" />
                <span>Loading version operations...</span>
              </div>
            {/if}
          </Collapsible.Content>
        </Collapsible.Root>
      </Card.Content>
    </Card.Root>
  </div>
</div>
