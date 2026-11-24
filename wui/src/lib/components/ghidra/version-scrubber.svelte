<script lang="ts">
  import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
  import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
  import CodeIcon from '@lucide/svelte/icons/code';
  import GitCompareIcon from '@lucide/svelte/icons/git-compare';
  import SearchCodeIcon from '@lucide/svelte/icons/search-code';
  import ScrubberDiffView from '#lib/components/ghidra/scrubber-diff-view.svelte';
  import ScrubberSidebar from '#lib/components/ghidra/scrubber-sidebar.svelte';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { getKeyedVariant, setKeyedVariant } from '#lib/components/ui/code-block/code-block-store.svelte.ts';
  import { CodeBlock, type CodeBlockVariant } from '#lib/components/ui/code-block/index.js';
  import * as Collapsible from '#lib/components/ui/collapsible/index.js';
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
    type SegmentInfo,
    type UrlNavState,
    type VersionDetail,
    type VersionSummary,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';

  let {
    paneSlot = 0,
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
    paneSlot?: number;
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

  const variantKey = $derived(`esperware-scrub-${paneSlot}`);

  let sidebarTab = $state<'versions' | 'functions'>('versions');
  let scrubMode = $state<'snapshot' | 'diff'>(untrack(() => initialNav?.scrubMode ?? 'snapshot'));
  let selectedVersion = $state(untrack(() => initialNav?.scrubVersion ?? 0));
  let scrubVersion = $state(untrack(() => initialNav?.scrubVersion ?? 0));
  let rangeFrom = $state(untrack(() => initialNav?.diffFrom ?? 0));
  let rangeTo = $state(untrack(() => initialNav?.diffTo ?? 0));
  let selectedFnAddr = $state(untrack(() => initialNav?.scrubFn ?? ''));
  let diffFnFilter = $state(untrack(() => initialNav?.scrubFn || '__all__'));
  let opsOpen = $state(false);
  let variantReady = $state(false);

  let fallbackFunctions = $state<FunctionRow[]>([]);
  let fallbackCodeMap = new SvelteMap<string, { name: string; code: string }>();
  let loadingTimeline = $state(false);
  let timelineError = $state<string | null>(null);

  let lastKnownMax = -1;
  let lastFocusSeq = 0;
  let timelineReqSeq = 0;
  let historyCtrl: AbortController | null = null;

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
    historyCtrl?.abort();
    const ctrl = new AbortController();
    historyCtrl = ctrl;

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
        if (req !== timelineReqSeq || ctrl.signal.aborted) return;
      }
      if (relevant.length === 0 && !hasFallback) {
        const detail = await client.functionDetail(addr, undefined, ctrl.signal);
        if (req !== timelineReqSeq || ctrl.signal.aborted) return;
        fallbackCodeMap.set(detail.function.address.toLowerCase(), {
          name: detail.function.name,
          code: detail.pseudocode || detail.decompile_error || '/* empty */',
        });
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === timelineReqSeq) {
        timelineError = error instanceof Error ? error.message : 'Failed to load version history.';
      }
    } finally {
      if (req === timelineReqSeq) {
        loadingTimeline = false;
      }
    }
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
      rangeFrom = Math.max(0, v.version - 1);
      rangeTo = v.version;
    }
  }

  function handleSidebarFnClick(address: string) {
    selectedFnAddr = address;
    diffFnFilter = address;
  }

  function switchScrubMode(nextMode: 'snapshot' | 'diff') {
    scrubMode = nextMode;
    if (nextMode === 'diff' && rangeTo === 0 && maxVersion > 0) {
      rangeFrom = Math.max(0, maxVersion - 1);
      rangeTo = maxVersion;
    }
  }

  // Keep version state synced when live SSE versions arrive.
  $effect(() => {
    const nextMax = maxVersion;
    const prevMax = lastKnownMax;
    if (prevMax === -1) {
      lastKnownMax = nextMax;
      untrack(() => {
        const initVer = initialNav?.scrubVersion !== undefined ? initialNav.scrubVersion : nextMax;
        setScrubVersion(initVer);
        variantReady = true;
        const initTo = initialNav?.diffTo !== undefined ? Math.max(0, Math.min(nextMax, initialNav.diffTo)) : nextMax;
        const initFrom =
          initialNav?.diffFrom !== undefined
            ? Math.max(0, Math.min(initTo, initialNav.diffFrom))
            : Math.max(0, nextMax - 1);
        rangeFrom = initFrom;
        rangeTo = initTo;
        if (scrubMode === 'diff') {
          selectedVersion = initTo;
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
    const ctrl = new AbortController();
    void (async () => {
      try {
        const res = await client.functions({ limit: 25 }, ctrl.signal);
        if (ctrl.signal.aborted) return;
        fallbackFunctions = res.functions.filter((f) => !f.external && !isExternalSegmentAddress(f.address, segments));
      } catch {
        // Primary error banner handles connection issues.
      }
    })();
    return () => {
      ctrl.abort();
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

  $effect(() => {
    return () => {
      historyCtrl?.abort();
    };
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

  // Sync CodeBlock header dropdown selection back to the slider once initialized.
  $effect(() => {
    if (!variantReady) return;
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
    if (!active) return;
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

<div class="grid grid-cols-1 items-start gap-4 @4xl:grid-cols-[290px_1fr]">
  <ScrubberSidebar
    {versionsDesc}
    {touchedFunctions}
    {sidebarTab}
    {selectedVersion}
    {activeFnAddr}
    onTabChange={(tab) => (sidebarTab = tab)}
    onVersionClick={handleSidebarVersionClick}
    onFnClick={handleSidebarFnClick}
  />

  <div class="flex min-w-0 flex-col gap-4">
    <Card.Root color="bright-black">
      <Card.Content class="flex flex-wrap items-center justify-between gap-3">
        <ButtonGroup.Root aria-label="Scrubber mode">
          <Button
            color={scrubMode === 'snapshot' ? 'cyan' : 'white'}
            size="sm"
            aria-pressed={scrubMode === 'snapshot'}
            onclick={() => switchScrubMode('snapshot')}
          >
            <CodeIcon />
            Snapshot Scrub
          </Button>
          <Button
            color={scrubMode === 'diff' ? 'magenta' : 'white'}
            size="sm"
            aria-pressed={scrubMode === 'diff'}
            onclick={() => switchScrubMode('diff')}
          >
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
      <ScrubberDiffView
        {client}
        {maxVersion}
        {selectedVersion}
        {diffFnFilter}
        {rangeFrom}
        {rangeTo}
        {formatVersionLabel}
        onRangeChange={(from, to) => {
          rangeFrom = from;
          rangeTo = to;
          selectedVersion = to;
        }}
      />
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
                <Button {...props} color="yellow" size="sm">
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
