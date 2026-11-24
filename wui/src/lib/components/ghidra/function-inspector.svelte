<script lang="ts">
  import ArrowUpDownIcon from '@lucide/svelte/icons/arrow-up-down';
  import BinaryIcon from '@lucide/svelte/icons/binary';
  import GitForkIcon from '@lucide/svelte/icons/git-fork';
  import HistoryIcon from '@lucide/svelte/icons/history';
  import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
  import FunctionListSidebar from '#lib/components/ghidra/function-list-sidebar.svelte';
  import FunctionVarsTables from '#lib/components/ghidra/function-vars-tables.svelte';
  import FunctionXrefsPanel from '#lib/components/ghidra/function-xrefs-panel.svelte';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import {
    addressKey,
    formatDisassembly,
    isExternalSegmentAddress,
    isReadableAddress,
    sameAddress,
    SHIKI_CONFIG,
    type DisasmInstruction,
    type FunctionDetailResponse,
    type FunctionRow,
    type FunctionSubView,
    type GhidraClient,
    type SegmentInfo,
    type UrlNavState,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    currentVersion,
    segments = [],
    active = true,
    touchedAddresses,
    lastVersionEvent = null,
    inspectRequest = null,
    initialNav = undefined,
    onScrubFunction,
    onOpenMemory,
    onNavChange = undefined,
  }: {
    client: GhidraClient;
    currentVersion: number;
    segments?: SegmentInfo[];
    active?: boolean;
    touchedAddresses: Set<string>;
    lastVersionEvent?: { version: number; operation: string; addresses: string[] } | null;
    inspectRequest?: { target: string; seq: number } | null;
    initialNav?: UrlNavState;
    onScrubFunction: (addr: string) => void;
    onOpenMemory: (addr: string, size?: number) => void;
    onNavChange?: (patch: Partial<UrlNavState>) => void;
  } = $props();

  let filterText = $state(untrack(() => initialNav?.fnFilter ?? ''));
  let sortBy = $state<'address' | 'name' | 'size'>(untrack(() => initialNav?.fnSort ?? 'address'));
  let functions = $state<FunctionRow[]>([]);
  let totalFunctions = $state(0);
  let nextCursor = $state<string | undefined>(undefined);
  let listLoading = $state(false);
  let listError = $state<string | null>(null);

  let selectedTarget = $state<string | null>(untrack(() => inspectRequest?.target ?? initialNav?.fnTarget ?? null));
  let failedTarget = $state<string | null>(null);
  let detail = $state<FunctionDetailResponse | null>(null);
  let pseudocodeText = $state('');
  let pseudocodeNextOffset = $state<number | undefined>(undefined);
  let detailLoading = $state(false);
  let detailError = $state<string | null>(null);

  let subView = $state<FunctionSubView>(
    untrack(() => (inspectRequest ? 'pseudocode' : (initialNav?.fnView ?? 'pseudocode'))),
  );

  let disasmRows = $state<DisasmInstruction[]>([]);
  let disasmScope = $state('');
  let disasmCursor = $state<string | undefined>(undefined);
  let disasmLoadedFor = $state<string | null>(null);
  let disasmLoading = $state(false);
  let disasmError = $state<string | null>(null);

  let listCtrl: AbortController | null = null;
  let detailCtrl: AbortController | null = null;
  let disasmCtrl: AbortController | null = null;

  let listReqSeq = 0;
  let detailReqSeq = 0;
  let disasmReqSeq = 0;
  let filterTimer: ReturnType<typeof setTimeout> | undefined;
  let lastInspectSeq = untrack(() => inspectRequest?.seq ?? 0);
  let hasLoadedList = false;
  let loadedVersion = -1;
  let loadedSort = untrack(() => sortBy);
  let hasSelectedOnce = Boolean(untrack(() => inspectRequest?.target ?? initialNav?.fnTarget));

  async function loadFunctionList(append = false) {
    if (filterTimer) {
      clearTimeout(filterTimer);
      filterTimer = undefined;
    }
    listCtrl?.abort();
    const ctrl = new AbortController();
    listCtrl = ctrl;

    const req = ++listReqSeq;
    listLoading = true;
    listError = null;
    try {
      const res = await client.functions(
        {
          filter: filterText.trim() || undefined,
          sort: sortBy,
          cursor: append ? nextCursor : undefined,
          limit: 100,
        },
        ctrl.signal,
      );
      if (req !== listReqSeq || ctrl.signal.aborted) return;
      functions = append ? [...functions, ...res.functions] : res.functions;
      totalFunctions = res.total;
      nextCursor = res.next_cursor;
      hasLoadedList = true;
      if (!append && !selectedTarget && !hasSelectedOnce && res.functions.length > 0) {
        const firstNonExt =
          res.functions.find((f) => !f.external && !isExternalSegmentAddress(f.address, segments)) ?? res.functions[0];
        void selectFunction(firstNonExt.address);
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === listReqSeq) {
        listError = error instanceof Error ? error.message : 'Failed to load functions.';
      }
    } finally {
      if (req === listReqSeq) {
        listLoading = false;
      }
    }
  }

  async function selectFunction(target: string, keepSubView = false) {
    detailCtrl?.abort();
    const ctrl = new AbortController();
    detailCtrl = ctrl;

    const keepExisting = keepSubView && detail !== null && sameAddress(detail.function.address, target);
    const req = ++detailReqSeq;
    hasSelectedOnce = true;
    selectedTarget = target;
    failedTarget = null;
    detailLoading = true;
    detailError = null;
    if (!keepSubView) subView = 'pseudocode';
    disasmLoadedFor = null;

    if (!keepExisting) {
      disasmCtrl?.abort();
      detail = null;
      pseudocodeText = '';
      pseudocodeNextOffset = undefined;
      disasmRows = [];
      disasmScope = '';
      disasmCursor = undefined;
      disasmError = null;
    }

    try {
      const res = await client.functionDetail(target, undefined, ctrl.signal);
      if (req !== detailReqSeq || ctrl.signal.aborted) return;
      detail = res;
      selectedTarget = res.function.address;
      pseudocodeText = res.pseudocode || res.decompile_error || '/* empty */';
      pseudocodeNextOffset = res.truncated ? res.next_offset : undefined;
      if (subView === 'disassembly') {
        void loadDisassembly(res.function.address, false);
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === detailReqSeq) {
        detail = null;
        selectedTarget = target;
        failedTarget = target;
        detailError = error instanceof Error ? error.message : 'Failed to decompile function.';
      }
    } finally {
      if (req === detailReqSeq) {
        detailLoading = false;
      }
    }
  }

  async function loadMorePseudocode() {
    if (!detail || pseudocodeNextOffset === undefined) return;
    detailCtrl?.abort();
    const ctrl = new AbortController();
    detailCtrl = ctrl;

    const req = ++detailReqSeq;
    detailLoading = true;
    detailError = null;
    try {
      const res = await client.functionDetail(detail.function.address, { offset: pseudocodeNextOffset }, ctrl.signal);
      if (req !== detailReqSeq || ctrl.signal.aborted) return;
      pseudocodeText += res.pseudocode;
      pseudocodeNextOffset = res.truncated ? res.next_offset : undefined;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === detailReqSeq) {
        detailError = error instanceof Error ? error.message : 'Failed to load next pseudocode chunk.';
      }
    } finally {
      if (req === detailReqSeq) {
        detailLoading = false;
      }
    }
  }

  async function loadDisassembly(target: string, append = false) {
    disasmCtrl?.abort();
    const ctrl = new AbortController();
    disasmCtrl = ctrl;

    const req = ++disasmReqSeq;
    disasmLoading = true;
    disasmError = null;
    try {
      const res = await client.functionDetail(
        target,
        {
          disasm: true,
          disasmCursor: append ? disasmCursor : undefined,
          maxInstructions: 200,
        },
        ctrl.signal,
      );
      if (req !== disasmReqSeq || ctrl.signal.aborted || !res.disassembly) return;
      disasmScope = res.disassembly.scope;
      disasmRows = append ? [...disasmRows, ...res.disassembly.instructions] : res.disassembly.instructions;
      disasmCursor = res.disassembly.next_cursor;
      disasmLoadedFor = target;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === disasmReqSeq) {
        disasmError = error instanceof Error ? error.message : 'Failed to load disassembly.';
      }
    } finally {
      if (req === disasmReqSeq) {
        disasmLoading = false;
      }
    }
  }

  function handleSubViewChange(next: FunctionSubView) {
    subView = next;
    const addr = detail?.function.address ?? selectedTarget;
    if (!addr) return;
    if (next === 'disassembly' && disasmLoadedFor !== addr) {
      void loadDisassembly(addr, false);
    }
  }

  function handleFilterInput() {
    if (filterTimer) clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
      void loadFunctionList(false);
    }, 180);
  }

  $effect(() => {
    const ver = currentVersion;
    const isActive = active;
    if (!isActive) return;
    untrack(() => {
      if (!hasLoadedList || loadedVersion !== ver) {
        const versionChanged = loadedVersion !== -1 && loadedVersion !== ver;
        loadedVersion = ver;
        loadedSort = sortBy;
        void loadFunctionList(false);
        const currentTarget = selectedTarget;
        if (currentTarget) {
          const shouldReloadDetail =
            !versionChanged ||
            !detail ||
            !lastVersionEvent ||
            lastVersionEvent.version !== ver ||
            lastVersionEvent.operation === 'define_type' ||
            lastVersionEvent.operation === 'revert' ||
            lastVersionEvent.addresses.some((addr) => sameAddress(addr, currentTarget));
          if (shouldReloadDetail) {
            void selectFunction(currentTarget, true);
          }
        }
      }
    });
  });

  $effect(() => {
    const nextSort = sortBy;
    const isActive = active;
    if (!isActive) return;
    untrack(() => {
      if (hasLoadedList && nextSort !== loadedSort) {
        loadedSort = nextSort;
        void loadFunctionList(false);
      }
    });
  });

  $effect(() => {
    return () => {
      if (filterTimer) {
        clearTimeout(filterTimer);
        filterTimer = undefined;
      }
      listCtrl?.abort();
      detailCtrl?.abort();
      disasmCtrl?.abort();
    };
  });

  $effect(() => {
    if (!inspectRequest || inspectRequest.seq === lastInspectSeq) return;
    lastInspectSeq = inspectRequest.seq;
    untrack(() => {
      void selectFunction(inspectRequest.target);
    });
  });

  $effect(() => {
    if (!active) return;
    const fnTarget = selectedTarget ?? undefined;
    const fnView = subView;
    const fnSort = sortBy;
    const fnFilter = filterText;
    untrack(() => {
      onNavChange?.({ fnTarget, fnView, fnSort, fnFilter });
    });
  });
</script>

<div class="grid grid-cols-1 items-start gap-4 @4xl:grid-cols-[300px_1fr]">
  <FunctionListSidebar
    {functions}
    {totalFunctions}
    {selectedTarget}
    {segments}
    bind:filterText
    {sortBy}
    {listLoading}
    {listError}
    hasMore={Boolean(nextCursor)}
    onFilterInput={handleFilterInput}
    onSortChange={(nextSort) => (sortBy = nextSort)}
    onSelect={(addr) => void selectFunction(addr)}
    onLoadMore={() => void loadFunctionList(true)}
  />

  <div class="flex min-w-0 flex-col gap-4">
    {#if detailError}
      <Alert.Root color="red">
        <Alert.Title>Decompile error</Alert.Title>
        <Alert.Description class="space-y-2">
          <p>{detailError}</p>
          <div class="flex flex-wrap items-center gap-2">
            {#if failedTarget}
              <Button color="yellow" size="sm" onclick={() => void selectFunction(failedTarget!, true)}>
                <RefreshCwIcon />
                Retry
              </Button>
            {/if}
            {#if failedTarget && isReadableAddress(failedTarget, segments)}
              <Button color="cyan" size="sm" onclick={() => onOpenMemory(failedTarget!)}>
                <BinaryIcon />
                Open @{failedTarget} in Memory
              </Button>
            {/if}
          </div>
        </Alert.Description>
      </Alert.Root>
    {/if}

    {#if detailLoading && !detail}
      <Card.Root color="white">
        <Card.Content class="flex items-center gap-3 py-8">
          <Spinner color="blue" />
          <span class="font-mono text-sm">Decompiling function...</span>
        </Card.Content>
      </Card.Root>
    {:else if detail}
      <Card.Root color="bright-black">
        <Card.Content class="space-y-3">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div class="min-w-0 space-y-1">
              <div class="flex flex-wrap items-center gap-2">
                <h2 class="my-0 font-mono text-xl font-black">{detail.function.name}</h2>
                <Badge color="yellow">@{detail.function.address}</Badge>
                <Badge color={detail.decompile_status === 'complete' ? 'green' : 'red'}>
                  {detail.decompile_status}
                </Badge>
              </div>
              <p class="font-mono text-xs break-all">{detail.function.signature}</p>
              {#if detail.function.comment}
                <p class="font-mono text-xs">/* {detail.function.comment} */</p>
              {/if}
            </div>

            <div class="flex flex-wrap items-center gap-2">
              {#if touchedAddresses.has(addressKey(detail.function.address))}
                <Button color="magenta" size="sm" onclick={() => onScrubFunction(detail!.function.address)}>
                  <HistoryIcon />
                  Scrub versions
                </Button>
              {/if}
              {#if isReadableAddress(detail.function.address, segments)}
                <Button color="green" size="sm" onclick={() => onOpenMemory(detail!.function.address)}>
                  <BinaryIcon />
                  Memory
                </Button>
              {/if}
            </div>
          </div>

          <ButtonGroup.Root aria-label="Function representation">
            <Button
              color={subView === 'pseudocode' ? 'cyan' : 'white'}
              size="sm"
              aria-pressed={subView === 'pseudocode'}
              onclick={() => handleSubViewChange('pseudocode')}
            >
              Pseudocode
            </Button>
            <Button
              color={subView === 'disassembly' ? 'magenta' : 'white'}
              size="sm"
              aria-pressed={subView === 'disassembly'}
              onclick={() => handleSubViewChange('disassembly')}
            >
              <ArrowUpDownIcon />
              Disassembly
            </Button>
            <Button
              color={subView === 'xrefs' ? 'yellow' : 'white'}
              size="sm"
              aria-pressed={subView === 'xrefs'}
              onclick={() => handleSubViewChange('xrefs')}
            >
              <GitForkIcon />
              Xrefs
            </Button>
          </ButtonGroup.Root>
        </Card.Content>
      </Card.Root>

      {#if subView === 'pseudocode'}
        <CodeBlock
          color="yellow"
          headerColor="blue"
          lang="c"
          title={`${detail.function.name} @ ${detail.function.address} (v${detail.version})`}
          code={pseudocodeText}
          shiki={SHIKI_CONFIG}
          numbered
          copy
          download={`${detail.function.name}.c`}
        />
        {#if pseudocodeNextOffset !== undefined}
          <Button color="cyan" size="sm" disabled={detailLoading} onclick={() => void loadMorePseudocode()}>
            Load next pseudocode chunk (offset {pseudocodeNextOffset})
          </Button>
        {/if}
      {:else if subView === 'disassembly'}
        {#if disasmError}
          <Alert.Root color="red">
            <Alert.Title>Disassembly error</Alert.Title>
            <Alert.Description>{disasmError}</Alert.Description>
          </Alert.Root>
        {:else if disasmLoading && disasmRows.length === 0}
          <Card.Root color="white">
            <Card.Content class="flex items-center gap-3 py-8">
              <Spinner color="magenta" />
              <span class="font-mono text-sm">Loading instructions...</span>
            </Card.Content>
          </Card.Root>
        {:else}
          <CodeBlock
            color="yellow"
            headerColor="magenta"
            lang="asm"
            title={disasmScope || `${detail.function.name} disassembly`}
            code={formatDisassembly(disasmRows)}
            shiki={SHIKI_CONFIG}
            copy
            download={`${detail.function.name}.asm`}
          />
          {#if disasmCursor}
            <Button
              color="blue"
              size="sm"
              disabled={disasmLoading}
              onclick={() => void loadDisassembly(detail!.function.address, true)}
            >
              Load more instructions
            </Button>
          {/if}
        {/if}
      {:else}
        <FunctionXrefsPanel
          {client}
          functionAddress={detail.function.address}
          {currentVersion}
          {segments}
          onSelectFunction={(addr) => void selectFunction(addr)}
          {onOpenMemory}
        />
      {/if}

      <FunctionVarsTables variables={detail.variables ?? []} globals={detail.globals ?? []} {segments} {onOpenMemory} />
    {:else if !detailError}
      <Alert.Root color="blue">
        <Alert.Title>Select a function</Alert.Title>
        <Alert.Description>
          Choose any function from the left list to inspect pseudocode, disassembly, variables, and xrefs.
        </Alert.Description>
      </Alert.Root>
    {/if}
  </div>
</div>
