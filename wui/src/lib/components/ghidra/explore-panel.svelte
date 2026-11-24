<script lang="ts">
  import BinaryIcon from '@lucide/svelte/icons/binary';
  import BookTypeIcon from '@lucide/svelte/icons/book-type';
  import SearchIcon from '@lucide/svelte/icons/search';
  import TagIcon from '@lucide/svelte/icons/tag';
  import ExploreMemoryTab from '#lib/components/ghidra/explore-memory-tab.svelte';
  import ExploreSearchTab from '#lib/components/ghidra/explore-search-tab.svelte';
  import ExploreSymbolsTab from '#lib/components/ghidra/explore-symbols-tab.svelte';
  import ExploreTypesTab from '#lib/components/ghidra/explore-types-tab.svelte';
  import * as Tabs from '#lib/components/ui/tabs/index.js';
  import {
    type ExploreSubTab,
    type GhidraClient,
    type MemoryFormat,
    type SearchScope,
    type SegmentInfo,
    type SymbolKind,
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

  let subTab = $state<ExploreSubTab>(untrack(() => (memoryRequest ? 'memory' : (initialNav?.exploreSub ?? 'symbols'))));
  let symbolKind = $state<SymbolKind>(untrack(() => initialNav?.symbolKind ?? 'strings'));
  let symbolFilter = $state(untrack(() => initialNav?.symbolFilter ?? ''));
  let typeQuery = $state(untrack(() => initialNav?.typeQuery || 'int'));
  let typeExact = $state(untrack(() => initialNav?.typeExact ?? false));
  let searchScope = $state<SearchScope>(untrack(() => initialNav?.searchScope ?? 'pseudocode'));
  let searchQuery = $state(untrack(() => initialNav?.searchQuery ?? ''));
  let memAddr = $state(untrack(() => initialNav?.memAddr ?? ''));
  let memSize = $state(untrack(() => initialNav?.memSize ?? 64));
  let memFormat = $state<MemoryFormat>(untrack(() => initialNav?.memFormat ?? 'hex'));

  let effectiveMemoryReq = $state<{ addr: string; size?: number; seq: number } | null>(null);
  let lastParentMemSeq = 0;
  let localMemSeq = 0;

  $effect.pre(() => {
    if (!memoryRequest || memoryRequest.seq === lastParentMemSeq) return;
    lastParentMemSeq = memoryRequest.seq;
    memAddr = memoryRequest.addr;
    if (memoryRequest.size !== undefined && Number.isFinite(memoryRequest.size) && memoryRequest.size >= 1) {
      memSize = Math.min(4096, Math.floor(memoryRequest.size));
    }
    effectiveMemoryReq = { addr: memoryRequest.addr, size: memoryRequest.size, seq: ++localMemSeq };
    subTab = 'memory';
  });

  function openAddressInMemory(addr: string, size?: number) {
    memAddr = addr;
    if (size !== undefined && Number.isFinite(size) && size >= 1) {
      memSize = Math.min(4096, Math.floor(size));
    }
    effectiveMemoryReq = { addr, size, seq: ++localMemSeq };
    subTab = 'memory';
  }

  $effect(() => {
    if (!active) return;
    const exploreSub = subTab;
    const sKind = symbolKind;
    const sFilter = symbolFilter;
    const tQuery = typeQuery;
    const tExact = typeExact;
    const scScope = searchScope;
    const scQuery = searchQuery;
    const mAddr = memAddr;
    const mSize = memSize;
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

  <Tabs.Content value="symbols">
    <ExploreSymbolsTab
      {client}
      {currentVersion}
      {segments}
      active={active && subTab === 'symbols'}
      initialKind={symbolKind}
      initialFilter={symbolFilter}
      {onInspectFunction}
      onOpenMemory={openAddressInMemory}
      onStateChange={(kind, filter) => {
        symbolKind = kind;
        symbolFilter = filter;
      }}
    />
  </Tabs.Content>

  <Tabs.Content value="types">
    <ExploreTypesTab
      {client}
      {currentVersion}
      active={active && subTab === 'types'}
      initialQuery={typeQuery}
      initialExact={typeExact}
      onStateChange={(query, exact) => {
        typeQuery = query;
        typeExact = exact;
      }}
    />
  </Tabs.Content>

  <Tabs.Content value="search">
    <ExploreSearchTab
      {client}
      {currentVersion}
      {segments}
      active={active && subTab === 'search'}
      initialScope={searchScope}
      initialQuery={searchQuery}
      {onInspectFunction}
      onOpenMemory={openAddressInMemory}
      onStateChange={(scope, query) => {
        searchScope = scope;
        searchQuery = query;
      }}
    />
  </Tabs.Content>

  <Tabs.Content value="memory">
    <ExploreMemoryTab
      {client}
      active={active && subTab === 'memory'}
      initialAddr={memAddr}
      initialSize={memSize}
      initialFormat={memFormat}
      memoryRequest={effectiveMemoryReq}
      onStateChange={(addr, size, format) => {
        memAddr = addr;
        memSize = size;
        memFormat = format;
      }}
    />
  </Tabs.Content>
</Tabs.Root>
