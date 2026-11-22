<script lang="ts">
  import ArrowUpDownIcon from '@lucide/svelte/icons/arrow-up-down';
  import BinaryIcon from '@lucide/svelte/icons/binary';
  import GitForkIcon from '@lucide/svelte/icons/git-fork';
  import HistoryIcon from '@lucide/svelte/icons/history';
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
  import {
    formatBytes,
    formatDisassembly,
    formatRouteError,
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
    type XrefKind,
    type XrefRow,
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

  let selectedTarget = $state<string | null>(untrack(() => initialNav?.fnTarget ?? null));
  let failedTarget = $state<string | null>(null);
  let detail = $state<FunctionDetailResponse | null>(null);
  let pseudocodeText = $state('');
  let pseudocodeNextOffset = $state<number | undefined>(undefined);
  let detailLoading = $state(false);
  let detailError = $state<string | null>(null);

  let subView = $state<FunctionSubView>(untrack(() => initialNav?.fnView ?? 'pseudocode'));

  let disasmRows = $state<DisasmInstruction[]>([]);
  let disasmScope = $state('');
  let disasmCursor = $state<string | undefined>(undefined);
  let disasmLoadedFor = $state<string | null>(null);
  let disasmLoading = $state(false);
  let disasmError = $state<string | null>(null);

  let xrefKind = $state<XrefKind>('all');
  let xrefRows = $state<XrefRow[]>([]);
  let xrefTotal = $state(0);
  let xrefCursor = $state<string | undefined>(undefined);
  let xrefsLoadedFor = $state<string | null>(null);
  let xrefsLoading = $state(false);
  let xrefsError = $state<string | null>(null);

  let listReqSeq = 0;
  let detailReqSeq = 0;
  let disasmReqSeq = 0;
  let xrefReqSeq = 0;
  let filterTimer: ReturnType<typeof setTimeout> | undefined;
  let lastInspectSeq = 0;
  let hasLoadedList = false;
  let loadedVersion = -1;
  let loadedSort = untrack(() => sortBy);
  let hasSelectedOnce = Boolean(untrack(() => initialNav?.fnTarget));

  async function loadFunctionList(append = false) {
    const req = ++listReqSeq;
    listLoading = true;
    listError = null;
    try {
      const res = await client.functions({
        filter: filterText.trim() || undefined,
        sort: sortBy,
        cursor: append ? nextCursor : undefined,
        limit: 100,
      });
      if (req !== listReqSeq) return;
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
    const req = ++detailReqSeq;
    hasSelectedOnce = true;
    selectedTarget = target;
    failedTarget = null;
    detail = null;
    pseudocodeText = '';
    pseudocodeNextOffset = undefined;
    detailLoading = true;
    detailError = null;
    disasmRows = [];
    disasmScope = '';
    disasmCursor = undefined;
    disasmLoadedFor = null;
    disasmError = null;
    xrefRows = [];
    xrefTotal = 0;
    xrefCursor = undefined;
    xrefsLoadedFor = null;
    xrefsError = null;
    if (!keepSubView) subView = 'pseudocode';

    try {
      const res = await client.functionDetail(target);
      if (req !== detailReqSeq) return;
      detail = res;
      selectedTarget = res.function.address;
      pseudocodeText = res.pseudocode || res.decompile_error || '/* empty */';
      pseudocodeNextOffset = res.truncated ? res.next_offset : undefined;
      if (subView === 'disassembly') {
        void loadDisassembly(res.function.address, false);
      } else if (subView === 'xrefs') {
        void loadXrefs(res.function.address, false);
      }
    } catch (error) {
      if (req === detailReqSeq) {
        detail = null;
        selectedTarget = null;
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
    const req = ++detailReqSeq;
    detailLoading = true;
    detailError = null;
    try {
      const res = await client.functionDetail(detail.function.address, { offset: pseudocodeNextOffset });
      if (req !== detailReqSeq) return;
      pseudocodeText += res.pseudocode;
      pseudocodeNextOffset = res.truncated ? res.next_offset : undefined;
    } catch (error) {
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
    const req = ++disasmReqSeq;
    disasmLoading = true;
    disasmError = null;
    try {
      const res = await client.functionDetail(target, {
        disasm: true,
        disasmCursor: append ? disasmCursor : undefined,
        maxInstructions: 200,
      });
      if (req !== disasmReqSeq || !res.disassembly) return;
      disasmScope = res.disassembly.scope;
      disasmRows = append ? [...disasmRows, ...res.disassembly.instructions] : res.disassembly.instructions;
      disasmCursor = res.disassembly.next_cursor;
      disasmLoadedFor = target;
    } catch (error) {
      if (req === disasmReqSeq) {
        disasmError = error instanceof Error ? error.message : 'Failed to load disassembly.';
      }
    } finally {
      if (req === disasmReqSeq) {
        disasmLoading = false;
      }
    }
  }

  async function loadXrefs(target: string, append = false) {
    const req = ++xrefReqSeq;
    xrefsLoading = true;
    xrefsError = null;
    if (!append) xrefTotal = 0;
    try {
      const res = await client.xrefs({
        target,
        kind: xrefKind,
        cursor: append ? xrefCursor : undefined,
        limit: 100,
      });
      if (req !== xrefReqSeq) return;
      xrefRows = append ? [...xrefRows, ...res.xrefs] : res.xrefs;
      xrefTotal = res.total;
      xrefCursor = res.next_cursor;
      xrefsLoadedFor = target;
    } catch (error) {
      if (req === xrefReqSeq) {
        xrefsError = formatRouteError('/api/v1/xrefs', error);
      }
    } finally {
      if (req === xrefReqSeq) {
        xrefsLoading = false;
      }
    }
  }

  function handleSubViewChange(next: 'pseudocode' | 'disassembly' | 'xrefs') {
    subView = next;
    const addr = detail?.function.address ?? selectedTarget;
    if (!addr) return;
    if (next === 'disassembly' && disasmLoadedFor !== addr) {
      void loadDisassembly(addr, false);
    } else if (next === 'xrefs' && xrefsLoadedFor !== addr) {
      void loadXrefs(addr, false);
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
        if (filterTimer) {
          clearTimeout(filterTimer);
          filterTimer = undefined;
        }
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
    const fnTarget = selectedTarget ?? undefined;
    const fnView = subView;
    const fnSort = sortBy;
    const fnFilter = filterText;
    untrack(() => {
      onNavChange?.({ fnTarget, fnView, fnSort, fnFilter });
    });
  });
</script>

<div class="grid grid-cols-1 items-start gap-4 lg:grid-cols-[330px_1fr]">
  <Card.Root color="bright-black" class="min-w-0">
    <Card.Header class="space-y-3">
      <Card.Title class="flex items-center justify-between gap-2 text-lg">
        <span>Functions</span>
        <Badge color="yellow">{totalFunctions}</Badge>
      </Card.Title>

      <Field.Field>
        <Field.Label for="fn-filter">Filter</Field.Label>
        <Input
          id="fn-filter"
          color="white"
          bind:value={filterText}
          placeholder="Name or address..."
          oninput={handleFilterInput}
        />
      </Field.Field>

      <ButtonGroup.Root class="w-full" aria-label="Sort functions">
        {#each ['address', 'name', 'size'] as const as opt (opt)}
          <Button
            color={sortBy === opt ? 'cyan' : 'white'}
            size="sm"
            class="flex-1 capitalize"
            onclick={() => (sortBy = opt)}
          >
            {opt}
          </Button>
        {/each}
      </ButtonGroup.Root>
    </Card.Header>

    <Card.Content class="space-y-3">
      {#if listError}
        <Alert.Root color="red">
          <Alert.Title>Error</Alert.Title>
          <Alert.Description>{listError}</Alert.Description>
        </Alert.Root>
      {/if}

      <div class="space-y-2 p-1">
        {#each functions as fn (fn.address)}
          {@const isSelected = sameAddress(selectedTarget, fn.address)}
          {@const isExt = fn.external || isExternalSegmentAddress(fn.address, segments)}
          <Item.Root
            color={isSelected ? 'cyan' : 'white'}
            size="sm"
            pressable
            class="mb-0 w-full cursor-pointer text-left"
          >
            {#snippet child({ props })}
              <button {...props} type="button" onclick={() => void selectFunction(fn.address)}>
                <Item.Content>
                  <Item.Header>
                    <Item.Title class="truncate font-mono">{fn.name}</Item.Title>
                    {#if isExt}
                      <Badge color="yellow">EXT</Badge>
                    {/if}
                  </Item.Header>
                  <div class="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                    <span>@{fn.address}</span>
                    <span>·</span>
                    <span>{formatBytes(fn.size)}</span>
                  </div>
                </Item.Content>
              </button>
            {/snippet}
          </Item.Root>
        {/each}

        {#if !listLoading && functions.length === 0}
          <p class="py-4 text-center font-mono text-xs">No matching functions.</p>
        {/if}
      </div>

      {#if listLoading}
        <div class="flex items-center justify-center gap-2 py-2 font-mono text-xs">
          <Spinner color="cyan" />
          <span>Loading functions...</span>
        </div>
      {/if}

      {#if nextCursor}
        <Button
          color="blue"
          size="sm"
          class="w-full"
          disabled={listLoading}
          onclick={() => void loadFunctionList(true)}
        >
          Load more functions
        </Button>
      {/if}
    </Card.Content>
  </Card.Root>

  <div class="flex min-w-0 flex-col gap-4">
    {#if detailError}
      <Alert.Root color="red">
        <Alert.Title>Decompile error</Alert.Title>
        <Alert.Description class="space-y-2">
          <p>{detailError}</p>
          {#if failedTarget && isReadableAddress(failedTarget, segments)}
            <Button color="cyan" size="sm" onclick={() => onOpenMemory(failedTarget!)}>
              <BinaryIcon />
              Open @{failedTarget} in Memory
            </Button>
          {/if}
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
                <h3 class="my-0 font-mono text-xl font-black">{detail.function.name}</h3>
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
              {#if touchedAddresses.has(detail.function.address.toLowerCase())}
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
              onclick={() => handleSubViewChange('pseudocode')}
            >
              Pseudocode
            </Button>
            <Button
              color={subView === 'disassembly' ? 'magenta' : 'white'}
              size="sm"
              onclick={() => handleSubViewChange('disassembly')}
            >
              <ArrowUpDownIcon />
              Disassembly
            </Button>
            <Button
              color={subView === 'xrefs' ? 'yellow' : 'white'}
              size="sm"
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
        <Card.Root color="bright-black">
          <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2">
            <Card.Title class="text-base">Cross-references ({xrefTotal})</Card.Title>
            <ButtonGroup.Root aria-label="Xref filter">
              {#each ['all', 'callers', 'callees', 'to', 'from'] as const as kind (kind)}
                <Button
                  color={xrefKind === kind ? 'yellow' : 'white'}
                  size="sm"
                  onclick={() => {
                    xrefKind = kind;
                    void loadXrefs(detail!.function.address, false);
                  }}
                >
                  {kind}
                </Button>
              {/each}
            </ButtonGroup.Root>
          </Card.Header>
          <Card.Content class="space-y-3">
            {#if xrefsError}
              <Alert.Root color="yellow">
                <Alert.Title>Xrefs unavailable</Alert.Title>
                <Alert.Description>{xrefsError}</Alert.Description>
              </Alert.Root>
            {:else if xrefsLoading && xrefRows.length === 0}
              <div class="flex items-center gap-2 py-4 font-mono text-xs">
                <Spinner color="yellow" />
                <span>Querying xrefs...</span>
              </div>
            {:else if xrefRows.length === 0}
              <Alert.Root color="blue">
                <Alert.Title>No matching cross-references</Alert.Title>
                <Alert.Description>Try another xref kind filter.</Alert.Description>
              </Alert.Root>
            {:else}
              <Table.Root headerColor="blue" rowColor="white">
                <Table.Header>
                  <Table.Row>
                    <Table.Head>Kind</Table.Head>
                    <Table.Head>Source / Target</Table.Head>
                    <Table.Head>Symbol / Function</Table.Head>
                    <Table.Head>Ref Type</Table.Head>
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {#each xrefRows as xr, idx (`${xr.kind}-${xr.address ?? xr.from_address}-${xr.to_address ?? idx}-${idx}`)}
                    <Table.Row>
                      <Table.Cell class="font-mono text-xs">
                        <Badge color={xr.kind === 'caller' || xr.kind === 'to' ? 'cyan' : 'yellow'}>
                          {xr.kind}
                        </Badge>
                      </Table.Cell>
                      <Table.Cell class="font-mono text-xs">
                        {#if xr.address}
                          {#if isExternalSegmentAddress(xr.address, segments)}
                            <div class="flex flex-wrap items-center gap-1.5">
                              <span>@{xr.address}</span>
                              <Badge color="yellow">EXT</Badge>
                            </div>
                          {:else}
                            <Button color="cyan" size="sm" onclick={() => void selectFunction(xr.address!)}>
                              @{xr.address}
                            </Button>
                          {/if}
                        {:else}
                          <span>{xr.from_address} → {xr.to_address}</span>
                        {/if}
                      </Table.Cell>
                      <Table.Cell class="font-mono text-xs">
                        {#if xr.name}
                          <span>{xr.name}</span>
                        {:else if xr.kind === 'to'}
                          {#if xr.from_function && (xr.from_function_address || xr.from_address)}
                            <Button
                              color="blue"
                              size="sm"
                              onclick={() => void selectFunction(xr.from_function_address ?? xr.from_address!)}
                            >
                              {xr.from_function}
                            </Button>
                          {:else if isReadableAddress(xr.from_address, segments)}
                            <Button color="green" size="sm" onclick={() => onOpenMemory(xr.from_address!)}>
                              @{xr.from_address}
                            </Button>
                          {:else}
                            <span>-</span>
                          {/if}
                        {:else if xr.kind === 'from'}
                          {@const isFnTarget = Boolean(
                            xr.to_is_function || (xr.ref_type && /CALL|JUMP/i.test(xr.ref_type)),
                          )}
                          {@const fnTarget = xr.to_function_address ?? xr.to_address}
                          {#if isFnTarget && fnTarget && !isExternalSegmentAddress(fnTarget, segments) && !/^Stack\[/i.test(fnTarget)}
                            <Button color="cyan" size="sm" onclick={() => void selectFunction(fnTarget)}>
                              {xr.to_symbol ?? `@${fnTarget}`}
                            </Button>
                          {:else if isReadableAddress(xr.to_address, segments)}
                            <Button color="green" size="sm" onclick={() => onOpenMemory(xr.to_address!)}>
                              {xr.to_symbol ?? `@${xr.to_address}`}
                            </Button>
                          {:else}
                            <span>{xr.to_symbol ?? '-'}</span>
                          {/if}
                        {:else}
                          <span>-</span>
                        {/if}
                      </Table.Cell>
                      <Table.Cell class="font-mono text-xs">{xr.ref_type ?? 'CALL'}</Table.Cell>
                    </Table.Row>
                  {/each}
                </Table.Body>
              </Table.Root>

              {#if xrefCursor}
                <Button
                  color="blue"
                  size="sm"
                  disabled={xrefsLoading}
                  onclick={() => void loadXrefs(detail!.function.address, true)}
                >
                  Load more xrefs
                </Button>
              {/if}
            {/if}
          </Card.Content>
        </Card.Root>
      {/if}

      {#if detail.variables && detail.variables.length > 0}
        <Card.Root color="bright-black">
          <Card.Header>
            <Card.Title class="text-base">Variables ({detail.variables.length})</Card.Title>
          </Card.Header>
          <Card.Content>
            <Table.Root headerColor="blue" rowColor="white">
              <Table.Header>
                <Table.Row>
                  <Table.Head>Kind</Table.Head>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>Type</Table.Head>
                  <Table.Head>Storage</Table.Head>
                  <Table.Head>Source</Table.Head>
                  <Table.Head>Comment</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each detail.variables as v, idx (`${v.kind}-${v.name}-${idx}`)}
                  <Table.Row>
                    <Table.Cell>
                      <Badge color={v.kind === 'parameter' ? 'cyan' : 'yellow'}>{v.kind}</Badge>
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs font-bold">{v.name}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">{v.data_type}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">{v.storage}</Table.Cell>
                    <Table.Cell>
                      <Badge color={v.source === 'db' ? 'green' : 'bright-black'}>{v.source}</Badge>
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs">{v.comment || '-'}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          </Card.Content>
        </Card.Root>
      {/if}

      {#if detail.globals && detail.globals.length > 0}
        <Card.Root color="bright-black">
          <Card.Header>
            <Card.Title class="text-base">Referenced Globals ({detail.globals.length})</Card.Title>
          </Card.Header>
          <Card.Content>
            <Table.Root headerColor="blue" rowColor="white">
              <Table.Header>
                <Table.Row>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>Address</Table.Head>
                  <Table.Head>Type</Table.Head>
                  <Table.Head>Size</Table.Head>
                  <Table.Head>Comment</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#each detail.globals as g (g.address)}
                  <Table.Row>
                    <Table.Cell class="font-mono text-xs font-bold">{g.name}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">
                      {#if isReadableAddress(g.address, segments)}
                        <Button
                          color="green"
                          size="sm"
                          onclick={() => onOpenMemory(g.address, Math.min(64, Math.max(1, g.size)))}
                        >
                          @{g.address}
                        </Button>
                      {:else}
                        <div class="flex flex-wrap items-center gap-1.5">
                          <span>@{g.address}</span>
                          <Badge color="bright-black">uninit</Badge>
                        </div>
                      {/if}
                    </Table.Cell>
                    <Table.Cell class="font-mono text-xs">{g.data_type}</Table.Cell>
                    <Table.Cell class="font-mono text-xs">{g.size} B</Table.Cell>
                    <Table.Cell class="font-mono text-xs">{g.comment || '-'}</Table.Cell>
                  </Table.Row>
                {/each}
              </Table.Body>
            </Table.Root>
          </Card.Content>
        </Card.Root>
      {/if}
    {:else if !detailError}
      <Alert.Root color="blue">
        <Alert.Title>Select a function</Alert.Title>
        <Alert.Description
          >Choose any function from the left list to inspect pseudocode, disassembly, variables, and xrefs.</Alert.Description
        >
      </Alert.Root>
    {/if}
  </div>
</div>
