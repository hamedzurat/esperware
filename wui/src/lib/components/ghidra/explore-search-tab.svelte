<script lang="ts">
  import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
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
    formatRouteError,
    isReadableAddress,
    type GhidraClient,
    type SearchMatch,
    type SearchScope,
    type SegmentInfo,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    currentVersion,
    segments = [],
    active = false,
    initialScope = 'pseudocode',
    initialQuery = '',
    onInspectFunction,
    onOpenMemory,
    onStateChange = undefined,
  }: {
    client: GhidraClient;
    currentVersion: number;
    segments?: SegmentInfo[];
    active?: boolean;
    initialScope?: SearchScope;
    initialQuery?: string;
    onInspectFunction: (target: string) => void;
    onOpenMemory: (addr: string, size?: number) => void;
    onStateChange?: (scope: SearchScope, query: string) => void;
  } = $props();

  const searchInputId = $props.id();

  let searchScope = $state<SearchScope>(untrack(() => initialScope));
  let searchQuery = $state(untrack(() => initialQuery));
  let searchMatches = $state<SearchMatch[]>([]);
  let searchCursor = $state<string | undefined>(undefined);
  let searchLoading = $state(false);
  let searchError = $state<string | null>(null);
  let searchNote = $state('');
  let searchHasRun = $state(false);
  let resultVersion = $state<number | null>(null);

  let reqCtrl: AbortController | null = null;
  let searchReqSeq = 0;
  let didInitialAutoRun = false;

  async function runSearch(append = false) {
    const q = searchQuery.trim();
    if (!q) {
      searchError = 'Enter text or hex bytes to search.';
      return;
    }
    reqCtrl?.abort();
    const ctrl = new AbortController();
    reqCtrl = ctrl;

    if (!append) {
      searchMatches = [];
      searchCursor = undefined;
      searchNote = '';
      resultVersion = null;
    }
    const req = ++searchReqSeq;
    searchLoading = true;
    searchError = null;
    try {
      const res = await client.search(
        {
          query: q,
          scope: searchScope,
          cursor: append ? searchCursor : undefined,
          limit: 25,
        },
        ctrl.signal,
      );
      if (req !== searchReqSeq || ctrl.signal.aborted) return;
      searchMatches = append ? [...searchMatches, ...res.matches] : res.matches;
      searchCursor = res.next_cursor;
      searchHasRun = true;
      resultVersion = res.version;
      if (res.scanned_functions !== undefined) {
        searchNote = `Scanned ${res.scanned_functions} functions`;
      } else if (res.scanned !== undefined) {
        searchNote = `Scanned ${res.scanned} instructions`;
      } else {
        searchNote = `${res.matches.length} matches`;
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === searchReqSeq) searchError = formatRouteError('/api/v1/search', error);
    } finally {
      if (req === searchReqSeq) searchLoading = false;
    }
  }

  $effect(() => {
    if (!active) return;
    untrack(() => {
      if (!didInitialAutoRun) {
        didInitialAutoRun = true;
        if (searchQuery.trim()) {
          void runSearch(false);
        }
      }
    });
  });

  $effect(() => {
    return () => {
      reqCtrl?.abort();
    };
  });

  $effect(() => {
    const scope = searchScope;
    const query = searchQuery;
    untrack(() => {
      onStateChange?.(scope, query);
    });
  });
</script>

<div class="space-y-4">
  <Card.Root color="bright-black">
    <Card.Content class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <ButtonGroup.Root aria-label="Search scope">
          {#each ['pseudocode', 'disassembly', 'bytes'] as const as scope (scope)}
            <Button
              color={searchScope === scope ? 'cyan' : 'white'}
              size="sm"
              aria-pressed={searchScope === scope}
              onclick={() => {
                reqCtrl?.abort();
                ++searchReqSeq;
                searchScope = scope;
                searchLoading = false;
                searchError = null;
                searchMatches = [];
                searchCursor = undefined;
                searchNote = '';
                searchHasRun = false;
                resultVersion = null;
              }}
            >
              {scope}
            </Button>
          {/each}
        </ButtonGroup.Root>

        {#if searchHasRun && resultVersion !== null && resultVersion !== currentVersion}
          <div class="flex items-center gap-2">
            <Badge color="yellow">Results from v{resultVersion}</Badge>
            <Button color="cyan" size="sm" disabled={searchLoading} onclick={() => void runSearch(false)}>
              <RefreshCwIcon />
              Refresh v{currentVersion}
            </Button>
          </div>
        {/if}
      </div>

      <form
        class="flex flex-wrap items-end gap-3"
        onsubmit={(e) => {
          e.preventDefault();
          void runSearch(false);
        }}
      >
        <Field.Field class="min-w-64 flex-1">
          <Field.Label for={searchInputId}>Query ({searchScope})</Field.Label>
          <Input
            id={searchInputId}
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
                <Button color="green" size="sm" onclick={() => onOpenMemory(m.address)}>
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
</div>
