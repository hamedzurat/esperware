<script lang="ts">
  import BinaryIcon from '@lucide/svelte/icons/binary';
  import BookTypeIcon from '@lucide/svelte/icons/book-type';
  import SearchIcon from '@lucide/svelte/icons/search';
  import TagIcon from '@lucide/svelte/icons/tag';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Table from '#lib/components/ui/table/index.js';
  import * as Tabs from '#lib/components/ui/tabs/index.js';
  import {
    findSegmentForAddress,
    formatRouteError,
    isReadableAddress,
    type ExploreSubTab,
    type GhidraClient,
    type MemoryFormat,
    type MemoryResponse,
    type SearchMatch,
    type SearchScope,
    type SegmentInfo,
    type SymbolKind,
    type SymbolRow,
    type TypeInfo,
    type UrlNavState,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    currentVersion,
    segments = [],
    active = true,
    memoryRequest = null,
    initialNav = undefined,
    onInspectFunction,
    onNavChange = undefined,
  }: {
    client: GhidraClient;
    currentVersion: number;
    segments?: SegmentInfo[];
    active?: boolean;
    memoryRequest?: { addr: string; size?: number; seq: number } | null;
    initialNav?: UrlNavState;
    onInspectFunction: (target: string) => void;
    onNavChange?: (patch: Partial<UrlNavState>) => void;
  } = $props();

  let subTab = $state<ExploreSubTab>(untrack(() => initialNav?.exploreSub ?? 'symbols'));

  // Symbols state
  let symbolKind = $state<SymbolKind>(untrack(() => initialNav?.symbolKind ?? 'strings'));
  let symbolFilter = $state(untrack(() => initialNav?.symbolFilter ?? ''));
  let symbolItems = $state<SymbolRow[]>([]);
  let symbolTotal = $state(0);
  let symbolCursor = $state<string | undefined>(undefined);
  let symbolsLoading = $state(false);
  let symbolsError = $state<string | null>(null);
  let symTimer: ReturnType<typeof setTimeout> | undefined;
  let symReqSeq = 0;
  let hasLoadedSymbols = false;
  let loadedSymKey = '';

  // Types state
  let typeQuery = $state(untrack(() => initialNav?.typeQuery || 'int'));
  let typeExact = $state(untrack(() => initialNav?.typeExact ?? false));
  let typeItems = $state<TypeInfo[]>([]);
  let typeTotal = $state(0);
  let typeCursor = $state<string | undefined>(undefined);
  let typesLoading = $state(false);
  let typesError = $state<string | null>(null);
  let typesHasRun = $state(false);
  let typeReqSeq = 0;

  // Search state
  let searchScope = $state<SearchScope>(untrack(() => initialNav?.searchScope ?? 'pseudocode'));
  let searchQuery = $state(untrack(() => initialNav?.searchQuery ?? ''));
  let searchMatches = $state<SearchMatch[]>([]);
  let searchCursor = $state<string | undefined>(undefined);
  let searchLoading = $state(false);
  let searchError = $state<string | null>(null);
  let searchNote = $state('');
  let searchHasRun = $state(false);
  let searchReqSeq = 0;

  // Memory state
  let memAddress = $state(untrack(() => initialNav?.memAddr ?? ''));
  let memSize = $state(untrack(() => initialNav?.memSize ?? 64));
  let memFormat = $state<MemoryFormat>(untrack(() => initialNav?.memFormat ?? 'hex'));
  let memResult = $state<MemoryResponse | null>(null);
  let memLoading = $state(false);
  let memError = $state<string | null>(null);
  let memReqSeq = 0;
  let lastMemorySeq = 0;
  let didRunInitialSubFetch = false;

  async function loadSymbols(append = false) {
    if (symTimer) {
      clearTimeout(symTimer);
      symTimer = undefined;
    }
    if (!append) {
      symbolItems = [];
      symbolCursor = undefined;
      symbolTotal = 0;
    }
    const req = ++symReqSeq;
    symbolsLoading = true;
    symbolsError = null;
    try {
      const res = await client.symbols({
        kind: symbolKind,
        filter: symbolFilter.trim() || undefined,
        cursor: append ? symbolCursor : undefined,
        limit: 100,
      });
      if (req !== symReqSeq) return;
      symbolItems = append ? [...symbolItems, ...res.items] : res.items;
      symbolTotal = res.total;
      symbolCursor = res.next_cursor;
    } catch (error) {
      if (req === symReqSeq) symbolsError = formatRouteError('/api/v1/symbols', error);
    } finally {
      if (req === symReqSeq) symbolsLoading = false;
    }
  }

  async function loadTypes(append = false) {
    const q = typeQuery.trim();
    if (!q) {
      typesError = 'Enter a type name or category path substring.';
      return;
    }
    if (!append) {
      typeItems = [];
      typeCursor = undefined;
      typeTotal = 0;
    }
    const req = ++typeReqSeq;
    typesLoading = true;
    typesError = null;
    try {
      const res = await client.types({
        query: q,
        exact: typeExact,
        cursor: append ? typeCursor : undefined,
        limit: 50,
      });
      if (req !== typeReqSeq) return;
      typeItems = append ? [...typeItems, ...res.types] : res.types;
      typeTotal = res.total;
      typeCursor = res.next_cursor;
      typesHasRun = true;
    } catch (error) {
      if (req === typeReqSeq) typesError = formatRouteError('/api/v1/types', error);
    } finally {
      if (req === typeReqSeq) typesLoading = false;
    }
  }

  async function runSearch(append = false) {
    const q = searchQuery.trim();
    if (!q) {
      searchError = 'Enter text or hex bytes to search.';
      return;
    }
    if (!append) {
      searchMatches = [];
      searchCursor = undefined;
      searchNote = '';
    }
    const req = ++searchReqSeq;
    searchLoading = true;
    searchError = null;
    try {
      const res = await client.search({
        query: q,
        scope: searchScope,
        cursor: append ? searchCursor : undefined,
        limit: 25,
      });
      if (req !== searchReqSeq) return;
      searchMatches = append ? [...searchMatches, ...res.matches] : res.matches;
      searchCursor = res.next_cursor;
      searchHasRun = true;
      if (res.scanned_functions !== undefined) {
        searchNote = `Scanned ${res.scanned_functions} functions`;
      } else if (res.scanned !== undefined) {
        searchNote = `Scanned ${res.scanned} instructions`;
      } else {
        searchNote = `${res.matches.length} matches`;
      }
    } catch (error) {
      if (req === searchReqSeq) searchError = formatRouteError('/api/v1/search', error);
    } finally {
      if (req === searchReqSeq) searchLoading = false;
    }
  }

  async function readMemory() {
    const addr = memAddress.trim();
    if (!addr) {
      memError = 'Enter a memory address to inspect.';
      return;
    }
    const req = ++memReqSeq;
    memLoading = true;
    memError = null;
    memResult = null;
    try {
      const parsed = Number(memSize);
      const clampedSize = Number.isFinite(parsed) && parsed >= 1 ? Math.min(4096, Math.floor(parsed)) : 64;
      memSize = clampedSize;
      const res = await client.memory({ address: addr, size: clampedSize, format: memFormat });
      if (req !== memReqSeq) return;
      memResult = res;
    } catch (error) {
      if (req === memReqSeq) memError = formatRouteError('/api/v1/memory', error);
    } finally {
      if (req === memReqSeq) memLoading = false;
    }
  }

  function openAddressInMemory(addr: string, size?: number) {
    memAddress = addr;
    if (size !== undefined && Number.isFinite(size) && size >= 1) {
      memSize = Math.min(4096, Math.floor(size));
    }
    subTab = 'memory';
    void readMemory();
  }

  function formatMemoryBlock(res: MemoryResponse): string {
    const lines = [`Address: ${res.address} (${res.size} bytes)`, `Hex: ${res.hex}`];
    if (res.utf8 !== undefined) {
      lines.push('', 'UTF-8:', res.utf8);
    }
    if (res.values !== undefined) {
      const wordBytes = res.format === 'u64' ? 8 : 4;
      lines.push(
        '',
        `${res.format.toUpperCase()} values:`,
        res.values.length > 0 ? res.values.join('  ') : `(need >= ${wordBytes} bytes)`,
      );
    }
    return lines.join('\n');
  }

  function formatTypeSummary(t: TypeInfo): string {
    if (t.fields && t.fields.length > 0) {
      const preview = t.fields
        .slice(0, 6)
        .map((f) => `+${f.offset} ${f.type} ${f.name}`)
        .join('; ');
      return t.fields.length > 6 || t.fields_truncated ? `${preview}; ...` : preview;
    }
    if (t.values && t.values.length > 0) {
      const preview = t.values
        .slice(0, 6)
        .map((v) => `${v.name}=${v.value}`)
        .join(', ');
      return t.values.length > 6 || t.values_truncated ? `${preview}, ...` : preview;
    }
    if (t.base_type) return `typedef -> ${t.base_type}`;
    if (t.points_to) return `ptr -> ${t.points_to}`;
    if (t.element_type) return `${t.element_type}[${t.element_count ?? '?'}]`;
    return t.description || '-';
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
      if (!didRunInitialSubFetch) {
        didRunInitialSubFetch = true;
        if (subTab === 'types' && typeQuery.trim()) {
          void loadTypes(false);
        } else if (subTab === 'search' && searchQuery.trim()) {
          void runSearch(false);
        } else if (subTab === 'memory' && memAddress.trim()) {
          void readMemory();
        }
      }
    });
  });

  $effect(() => {
    const isActive = active;
    const sub = subTab;
    if (!isActive || sub !== 'types') return;
    untrack(() => {
      if (!typesHasRun && !typesLoading && typeQuery.trim()) {
        void loadTypes(false);
      }
    });
  });

  $effect(() => {
    return () => {
      if (symTimer) {
        clearTimeout(symTimer);
        symTimer = undefined;
      }
    };
  });

  $effect(() => {
    if (!memoryRequest || memoryRequest.seq === lastMemorySeq) return;
    lastMemorySeq = memoryRequest.seq;
    untrack(() => {
      openAddressInMemory(memoryRequest.addr, memoryRequest.size);
    });
  });

  $effect(() => {
    const exploreSub = subTab;
    const sKind = symbolKind;
    const sFilter = symbolFilter;
    const tQuery = typeQuery;
    const tExact = typeExact;
    const scScope = searchScope;
    const scQuery = searchQuery;
    const mAddr = memAddress;
    const mSize = Number(memSize) || 64;
    const mFmt = memFormat;
    untrack(() => {
      onNavChange?.({
        exploreSub,
        symbolKind: sKind,
        symbolFilter: sFilter,
        typeQuery: tQuery,
        typeExact: tExact,
        searchScope: scScope,
        searchQuery: scQuery,
        memAddr: mAddr,
        memSize: mSize,
        memFormat: mFmt,
      });
    });
  });
</script>

<Tabs.Root bind:value={subTab} activeColor="yellow" inactiveColor="white" class="space-y-4">
  <Tabs.List>
    <Tabs.Trigger value="symbols">
      <TagIcon />
      Symbols
    </Tabs.Trigger>
    <Tabs.Trigger value="types">
      <BookTypeIcon />
      Types
    </Tabs.Trigger>
    <Tabs.Trigger value="search">
      <SearchIcon />
      Search
    </Tabs.Trigger>
    <Tabs.Trigger value="memory">
      <BinaryIcon />
      Memory
    </Tabs.Trigger>
  </Tabs.List>

  <Tabs.Content value="symbols" class="space-y-4">
    <Card.Root color="bright-black">
      <Card.Content class="flex flex-wrap items-end justify-between gap-4">
        <div class="space-y-2">
          <div class="font-mono text-xs font-bold">Category ({symbolTotal})</div>
          <ButtonGroup.Root class="flex-wrap" aria-label="Symbol category">
            {#each ['strings', 'imports', 'exports', 'globals', 'classes', 'namespaces'] as const as kind (kind)}
              <Button color={symbolKind === kind ? 'yellow' : 'white'} size="sm" onclick={() => (symbolKind = kind)}>
                {kind}
              </Button>
            {/each}
          </ButtonGroup.Root>
        </div>

        <Field.Field class="min-w-56 flex-1 sm:max-w-xs">
          <Field.Label for="sym-filter">Filter</Field.Label>
          <Input
            id="sym-filter"
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
                      <Button color="green" size="sm" onclick={() => openAddressInMemory(item.address!, byteSize)}>
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
  </Tabs.Content>

  <Tabs.Content value="types" class="space-y-4">
    <Card.Root color="bright-black">
      <Card.Content class="space-y-3">
        <form
          class="flex flex-wrap items-end gap-3"
          onsubmit={(e) => {
            e.preventDefault();
            void loadTypes(false);
          }}
        >
          <Field.Field class="min-w-56 flex-1">
            <Field.Label for="type-query">Type Query</Field.Label>
            <Input id="type-query" color="white" bind:value={typeQuery} placeholder="Struct, enum, or path..." />
          </Field.Field>
          <Button
            color={typeExact ? 'cyan' : 'white'}
            size="sm"
            aria-pressed={typeExact}
            onclick={() => {
              typeExact = !typeExact;
              if (typeQuery.trim()) void loadTypes(false);
            }}
          >
            Exact: {typeExact ? 'ON' : 'OFF'}
          </Button>
          <Button type="submit" color="green" disabled={typesLoading}>
            {#if typesLoading}
              <Spinner />
            {/if}
            Search types
          </Button>
        </form>

        <div class="flex flex-wrap items-center gap-1.5">
          <span class="font-mono text-xs font-bold">Quick:</span>
          {#each ['int', 'uint', 'char', 'void', '/mcp'] as const as preset (preset)}
            <Button
              color="yellow"
              size="sm"
              onclick={() => {
                typeQuery = preset;
                typeExact = false;
                void loadTypes(false);
              }}
            >
              {preset}
            </Button>
          {/each}
          {#if typeTotal > 0}
            <Badge color="cyan">{typeTotal} matches</Badge>
          {/if}
        </div>
      </Card.Content>
    </Card.Root>

    {#if typesError}
      <Alert.Root color="yellow">
        <Alert.Title>Types notice</Alert.Title>
        <Alert.Description>{typesError}</Alert.Description>
      </Alert.Root>
    {/if}

    {#if typesLoading && typeItems.length === 0}
      <Card.Root color="white">
        <Card.Content class="flex items-center gap-3 py-6">
          <Spinner color="cyan" />
          <span class="font-mono text-sm">Searching data types...</span>
        </Card.Content>
      </Card.Root>
    {:else if typeItems.length > 0}
      <Table.Root headerColor="blue" rowColor="white">
        <Table.Header>
          <Table.Row>
            <Table.Head>Name</Table.Head>
            <Table.Head>Kind</Table.Head>
            <Table.Head>Size</Table.Head>
            <Table.Head>Path</Table.Head>
            <Table.Head>Layout / Target</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each typeItems as t (t.path)}
            <Table.Row>
              <Table.Cell class="font-mono text-xs font-bold">{t.name}</Table.Cell>
              <Table.Cell><Badge color="yellow">{t.kind}</Badge></Table.Cell>
              <Table.Cell class="font-mono text-xs">{t.size} B</Table.Cell>
              <Table.Cell class="font-mono text-xs break-all">{t.path}</Table.Cell>
              <Table.Cell class="font-mono text-xs break-all">{formatTypeSummary(t)}</Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>

      {#if typeCursor}
        <Button color="blue" size="sm" disabled={typesLoading} onclick={() => void loadTypes(true)}>
          Load more types
        </Button>
      {/if}
    {:else if typesHasRun && !typesError}
      <Alert.Root color="blue">
        <Alert.Title>No matching types</Alert.Title>
        <Alert.Description>Try a broader substring or toggle Exact OFF.</Alert.Description>
      </Alert.Root>
    {/if}
  </Tabs.Content>

  <Tabs.Content value="search" class="space-y-4">
    <Card.Root color="bright-black">
      <Card.Content class="space-y-3">
        <ButtonGroup.Root aria-label="Search scope">
          {#each ['pseudocode', 'disassembly', 'bytes'] as const as scope (scope)}
            <Button
              color={searchScope === scope ? 'cyan' : 'white'}
              size="sm"
              onclick={() => {
                ++searchReqSeq;
                searchScope = scope;
                searchLoading = false;
                searchError = null;
                searchMatches = [];
                searchCursor = undefined;
                searchNote = '';
                searchHasRun = false;
              }}
            >
              {scope}
            </Button>
          {/each}
        </ButtonGroup.Root>

        <form
          class="flex flex-wrap items-end gap-3"
          onsubmit={(e) => {
            e.preventDefault();
            void runSearch(false);
          }}
        >
          <Field.Field class="min-w-64 flex-1">
            <Field.Label for="code-search">Query ({searchScope})</Field.Label>
            <Input
              id="code-search"
              color="white"
              bind:value={searchQuery}
              placeholder={searchScope === 'bytes'
                ? 'Hex pattern e.g. 55 48 ?? e5'
                : searchScope === 'disassembly'
                  ? 'Mnemonic or operand e.g. MOV RDI'
                  : 'Substring across decompiled C...'}
            />
          </Field.Field>
          <Button type="submit" color="green" disabled={searchLoading}>
            {#if searchLoading}
              <Spinner />
            {/if}
            Search
          </Button>
        </form>

        {#if searchNote}
          <div class="font-mono text-xs">{searchNote}</div>
        {/if}
      </Card.Content>
    </Card.Root>

    {#if searchError}
      <Alert.Root color="yellow">
        <Alert.Title>Search notice</Alert.Title>
        <Alert.Description>{searchError}</Alert.Description>
      </Alert.Root>
    {/if}

    {#if searchMatches.length > 0}
      <Table.Root headerColor="blue" rowColor="white">
        <Table.Header>
          <Table.Row>
            <Table.Head>Address</Table.Head>
            <Table.Head>Function</Table.Head>
            <Table.Head>Match</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each searchMatches as m, idx (`${m.address}-${idx}`)}
            <Table.Row>
              <Table.Cell class="font-mono text-xs">
                {#if isReadableAddress(m.address, segments)}
                  <Button color="green" size="sm" onclick={() => openAddressInMemory(m.address)}>
                    @{m.address}
                  </Button>
                {:else}
                  <span>@{m.address}</span>
                {/if}
              </Table.Cell>
              <Table.Cell class="font-mono text-xs">
                {#if m.name || m.function}
                  <Button color="cyan" size="sm" onclick={() => onInspectFunction(m.address)}>
                    {m.name ?? m.function}
                  </Button>
                {:else}
                  <span>-</span>
                {/if}
              </Table.Cell>
              <Table.Cell class="max-w-xl font-mono text-xs break-all">
                {m.excerpt ?? m.instruction ?? (m.function ? `in ${m.function}` : 'byte match')}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>

      {#if searchCursor}
        <Button color="blue" size="sm" disabled={searchLoading} onclick={() => void runSearch(true)}>
          Continue search page
        </Button>
      {/if}
    {:else if searchHasRun && !searchLoading && !searchError}
      <Alert.Root color="blue">
        <Alert.Title>No matches found</Alert.Title>
        <Alert.Description>Try another query string, hex pattern, or search scope.</Alert.Description>
      </Alert.Root>
    {/if}
  </Tabs.Content>

  <Tabs.Content value="memory" class="space-y-4">
    <Card.Root color="bright-black">
      <Card.Content>
        <form
          class="flex flex-wrap items-end gap-3"
          onsubmit={(e) => {
            e.preventDefault();
            void readMemory();
          }}
        >
          <Field.Field class="min-w-44 flex-1">
            <Field.Label for="mem-addr">Address</Field.Label>
            <Input id="mem-addr" color="white" bind:value={memAddress} placeholder="0x401000 or 00401000" />
          </Field.Field>

          <Field.Field class="w-28">
            <Field.Label for="mem-size">Bytes</Field.Label>
            <Input id="mem-size" color="white" type="number" min={1} max={4096} bind:value={memSize} />
          </Field.Field>

          <div class="space-y-2">
            <div class="font-mono text-xs font-bold">Format</div>
            <ButtonGroup.Root aria-label="Memory format">
              {#each ['hex', 'utf8', 'u32', 'u64'] as const as fmt (fmt)}
                <Button
                  color={memFormat === fmt ? 'cyan' : 'white'}
                  size="sm"
                  onclick={() => {
                    memFormat = fmt;
                    if (memAddress.trim()) void readMemory();
                  }}
                >
                  {fmt}
                </Button>
              {/each}
            </ButtonGroup.Root>
          </div>

          <Button type="submit" color="green" disabled={memLoading}>
            {#if memLoading}
              <Spinner />
            {/if}
            Read
          </Button>
        </form>
      </Card.Content>
    </Card.Root>

    {#if memError}
      <Alert.Root color="yellow">
        <Alert.Title>Memory read failed</Alert.Title>
        <Alert.Description>{memError}</Alert.Description>
      </Alert.Root>
    {:else if memResult}
      <CodeBlock
        color="yellow"
        headerColor="blue"
        title={`Memory @ ${memResult.address} (${memResult.size} B · ${memResult.format})`}
        code={formatMemoryBlock(memResult)}
        copy
      />
    {/if}
  </Tabs.Content>
</Tabs.Root>
