<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Table from '#lib/components/ui/table/index.js';
  import {
    findSegmentForAddress,
    formatRouteError,
    isReadableAddress,
    type GhidraClient,
    type SegmentInfo,
    type SymbolKind,
    type SymbolRow,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    currentVersion,
    segments = [],
    active = false,
    initialKind = 'strings',
    initialFilter = '',
    onInspectFunction,
    onOpenMemory,
    onStateChange = undefined,
  }: {
    client: GhidraClient;
    currentVersion: number;
    segments?: SegmentInfo[];
    active?: boolean;
    initialKind?: SymbolKind;
    initialFilter?: string;
    onInspectFunction: (target: string) => void;
    onOpenMemory: (addr: string, size?: number) => void;
    onStateChange?: (kind: SymbolKind, filter: string) => void;
  } = $props();

  const filterInputId = $props.id();

  let symbolKind = $state<SymbolKind>(untrack(() => initialKind));
  let symbolFilter = $state(untrack(() => initialFilter));
  let symbolItems = $state<SymbolRow[]>([]);
  let symbolTotal = $state(0);
  let symbolCursor = $state<string | undefined>(undefined);
  let symbolsLoading = $state(false);
  let symbolsError = $state<string | null>(null);

  let symTimer: ReturnType<typeof setTimeout> | undefined;
  let reqCtrl: AbortController | null = null;
  let symReqSeq = 0;
  let hasLoadedSymbols = false;
  let loadedSymKey = '';

  async function loadSymbols(append = false) {
    if (symTimer) {
      clearTimeout(symTimer);
      symTimer = undefined;
    }
    reqCtrl?.abort();
    const ctrl = new AbortController();
    reqCtrl = ctrl;

    if (!append) {
      symbolItems = [];
      symbolCursor = undefined;
      symbolTotal = 0;
    }
    const req = ++symReqSeq;
    symbolsLoading = true;
    symbolsError = null;
    try {
      const res = await client.symbols(
        {
          kind: symbolKind,
          filter: symbolFilter.trim() || undefined,
          cursor: append ? symbolCursor : undefined,
          limit: 100,
        },
        ctrl.signal,
      );
      if (req !== symReqSeq || ctrl.signal.aborted) return;
      symbolItems = append ? [...symbolItems, ...res.items] : res.items;
      symbolTotal = res.total;
      symbolCursor = res.next_cursor;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === symReqSeq) symbolsError = formatRouteError('/api/v1/symbols', error);
    } finally {
      if (req === symReqSeq) symbolsLoading = false;
    }
  }

  $effect(() => {
    const ver = currentVersion;
    const kind = symbolKind;
    const isActive = active;
    if (!isActive) return;
    untrack(() => {
      const symKey = `${ver}:${kind}`;
      if (!hasLoadedSymbols || loadedSymKey !== symKey) {
        hasLoadedSymbols = true;
        loadedSymKey = symKey;
        void loadSymbols(false);
      }
    });
  });

  $effect(() => {
    return () => {
      if (symTimer) {
        clearTimeout(symTimer);
        symTimer = undefined;
      }
      reqCtrl?.abort();
    };
  });

  $effect(() => {
    const kind = symbolKind;
    const filter = symbolFilter;
    untrack(() => {
      onStateChange?.(kind, filter);
    });
  });
</script>

<div class="space-y-4">
  <Card.Root color="bright-black">
    <Card.Content class="flex flex-wrap items-end justify-between gap-4">
      <div class="space-y-2">
        <div class="font-mono text-xs font-bold">Category ({symbolTotal})</div>
        <ButtonGroup.Root class="flex-wrap" aria-label="Symbol category">
          {#each ['strings', 'imports', 'exports', 'globals', 'classes', 'namespaces'] as const as kind (kind)}
            <Button
              color={symbolKind === kind ? 'yellow' : 'white'}
              size="sm"
              aria-pressed={symbolKind === kind}
              onclick={() => (symbolKind = kind)}
            >
              {kind}
            </Button>
          {/each}
        </ButtonGroup.Root>
      </div>

      <Field.Field class="min-w-56 flex-1 sm:max-w-xs">
        <Field.Label for={filterInputId}>Filter</Field.Label>
        <Input
          id={filterInputId}
          color="white"
          bind:value={symbolFilter}
          placeholder="Name, text, or address..."
          oninput={() => {
            if (symTimer) clearTimeout(symTimer);
            symTimer = setTimeout(() => void loadSymbols(false), 180);
          }}
        />
      </Field.Field>
    </Card.Content>
  </Card.Root>

  {#if symbolsError}
    <Alert.Root color="yellow">
      <Alert.Title>Symbols unavailable</Alert.Title>
      <Alert.Description>{symbolsError}</Alert.Description>
    </Alert.Root>
  {/if}

  {#if symbolsLoading && symbolItems.length === 0}
    <Card.Root color="white">
      <Card.Content class="flex items-center gap-3 py-6">
        <Spinner color="yellow" />
        <span class="font-mono text-sm">Loading {symbolKind}...</span>
      </Card.Content>
    </Card.Root>
  {:else if symbolItems.length > 0}
    <Table.Root headerColor="blue" rowColor="white">
      <Table.Header>
        <Table.Row>
          <Table.Head>Address / ID</Table.Head>
          <Table.Head>Name / Value</Table.Head>
          <Table.Head>Type</Table.Head>
          <Table.Head>Meta</Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each symbolItems as item, idx (`${item.address ?? item.id ?? idx}-${idx}`)}
          {@const symSeg = item.address ? findSegmentForAddress(item.address, segments) : null}
          {@const canInspectFn = Boolean(
            item.address &&
            !item.address.startsWith('EXTERNAL:') &&
            (item.type === 'Function' || (item.type === 'Label' && symSeg?.execute)),
          )}
          {@const canReadMem = isReadableAddress(item.address, segments)}
          {@const byteSize = item.size ?? item.length}
          <Table.Row>
            <Table.Cell class="font-mono text-xs">
              {#if item.address}
                <div class="flex flex-wrap items-center gap-1.5">
                  {#if canInspectFn}
                    <Button color="cyan" size="sm" onclick={() => onInspectFunction(item.address!)}>
                      Inspect @{item.address}
                    </Button>
                  {/if}
                  {#if canReadMem}
                    <Button color="green" size="sm" onclick={() => onOpenMemory(item.address!, byteSize)}>
                      {canInspectFn ? 'Mem' : `@${item.address}`}
                    </Button>
                  {/if}
                  {#if !canInspectFn && !canReadMem}
                    <span>@{item.address}</span>
                    <Badge color="bright-black">
                      {item.address.startsWith('EXTERNAL:') ? 'external' : 'uninit'}
                    </Badge>
                  {/if}
                </div>
              {:else}
                <span>id:{item.id ?? '-'}</span>
              {/if}
            </Table.Cell>
            <Table.Cell class="max-w-md font-mono text-xs break-all">
              {item.value ?? item.full_name ?? item.name ?? '-'}
            </Table.Cell>
            <Table.Cell class="font-mono text-xs">{item.data_type ?? item.type ?? '-'}</Table.Cell>
            <Table.Cell class="font-mono text-xs">
              {item.size !== undefined
                ? `${item.size} B`
                : item.length !== undefined
                  ? `${item.length} B`
                  : (item.source ?? '-')}
            </Table.Cell>
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>

    {#if symbolCursor}
      <Button color="blue" size="sm" disabled={symbolsLoading} onclick={() => void loadSymbols(true)}>
        Load more symbols
      </Button>
    {/if}
  {:else if !symbolsError}
    <Alert.Root color="blue">
      <Alert.Title>No matching {symbolKind}</Alert.Title>
      <Alert.Description>Try clearing the filter or choosing another symbol category.</Alert.Description>
    </Alert.Root>
  {/if}
</div>
