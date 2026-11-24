<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Table from '#lib/components/ui/table/index.js';
  import { formatRouteError, type GhidraClient, type TypeInfo } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';

  let {
    client,
    currentVersion,
    active = false,
    initialQuery = 'int',
    initialExact = false,
    onStateChange = undefined,
  }: {
    client: GhidraClient;
    currentVersion: number;
    active?: boolean;
    initialQuery?: string;
    initialExact?: boolean;
    onStateChange?: (query: string, exact: boolean) => void;
  } = $props();

  const queryInputId = $props.id();

  let typeQuery = $state(untrack(() => initialQuery || 'int'));
  let typeExact = $state(untrack(() => initialExact));
  let typeItems = $state<TypeInfo[]>([]);
  let typeTotal = $state(0);
  let typeCursor = $state<string | undefined>(undefined);
  let typesLoading = $state(false);
  let typesError = $state<string | null>(null);
  let typesHasRun = $state(false);

  const expandedPaths = new SvelteSet<string>();

  let reqCtrl: AbortController | null = null;
  let typeReqSeq = 0;
  let loadedVersion = -1;
  let lastSubmittedQuery = '';
  let lastSubmittedExact = false;

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

  function formatTypeFull(t: TypeInfo): string[] {
    if (t.fields && t.fields.length > 0) {
      const lines = t.fields.map((f) => `+${f.offset} ${f.type} ${f.name} (${f.size} B)`);
      if (t.fields_truncated) lines.push('... (truncated at 100 fields)');
      return lines;
    }
    if (t.values && t.values.length > 0) {
      const lines = t.values.map((v) => `${v.name} = ${v.value}`);
      if (t.values_truncated) lines.push('... (truncated at 100 values)');
      return lines;
    }
    return [];
  }

  function isExpandable(t: TypeInfo): boolean {
    return Boolean((t.fields && t.fields.length > 6) || (t.values && t.values.length > 6));
  }

  function toggleExpand(path: string) {
    if (expandedPaths.has(path)) expandedPaths.delete(path);
    else expandedPaths.add(path);
  }

  async function loadTypes(append = false, override?: { query: string; exact: boolean }) {
    const q = (override ? override.query : typeQuery).trim();
    const exact = override ? override.exact : typeExact;
    if (!q) {
      typesError = 'Enter a type name or category path substring.';
      return;
    }
    reqCtrl?.abort();
    const ctrl = new AbortController();
    reqCtrl = ctrl;

    if (!append) {
      typeItems = [];
      typeCursor = undefined;
      typeTotal = 0;
      expandedPaths.clear();
    }
    const req = ++typeReqSeq;
    loadedVersion = currentVersion;
    lastSubmittedQuery = q;
    lastSubmittedExact = exact;
    typesLoading = true;
    typesError = null;
    try {
      const res = await client.types(
        {
          query: q,
          exact,
          cursor: append ? typeCursor : undefined,
          limit: 50,
        },
        ctrl.signal,
      );
      if (req !== typeReqSeq || ctrl.signal.aborted) return;
      typeItems = append ? [...typeItems, ...res.types] : res.types;
      typeTotal = res.total;
      typeCursor = res.next_cursor;
      typesHasRun = true;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === typeReqSeq) typesError = formatRouteError('/api/v1/types', error);
    } finally {
      if (req === typeReqSeq) typesLoading = false;
    }
  }

  $effect(() => {
    const isActive = active;
    const ver = currentVersion;
    if (!isActive) return;
    untrack(() => {
      if (!typesHasRun && !typesLoading && typeQuery.trim().length > 0) {
        void loadTypes(false);
      } else if (typesHasRun && loadedVersion !== -1 && loadedVersion !== ver && lastSubmittedQuery.length > 0) {
        void loadTypes(false, { query: lastSubmittedQuery, exact: lastSubmittedExact });
      }
    });
  });

  $effect(() => {
    return () => {
      reqCtrl?.abort();
    };
  });

  $effect(() => {
    const query = typeQuery;
    const exact = typeExact;
    untrack(() => {
      onStateChange?.(query, exact);
    });
  });
</script>

<div class="space-y-4">
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
          <Field.Label for={queryInputId}>Type Query</Field.Label>
          <Input id={queryInputId} color="white" bind:value={typeQuery} placeholder="Struct, enum, or path..." />
        </Field.Field>
        <Button
          type="button"
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
            <Table.Cell class="font-mono text-xs break-all">
              {#if expandedPaths.has(t.path)}
                <div class="space-y-1">
                  {#each formatTypeFull(t) as line, idx (`${t.path}-${idx}`)}
                    <div>{line}</div>
                  {/each}
                </div>
              {:else}
                <div>{formatTypeSummary(t)}</div>
              {/if}
              {#if isExpandable(t)}
                {@const count = t.fields?.length ?? t.values?.length ?? 0}
                <div class="mt-1.5">
                  <Button
                    color="cyan"
                    size="sm"
                    aria-expanded={expandedPaths.has(t.path)}
                    onclick={() => toggleExpand(t.path)}
                  >
                    {expandedPaths.has(t.path) ? 'Collapse' : `Show all ${count}`}
                  </Button>
                </div>
              {/if}
            </Table.Cell>
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>

    {#if typeCursor}
      <Button
        color="blue"
        size="sm"
        disabled={typesLoading}
        onclick={() => void loadTypes(true, { query: lastSubmittedQuery || typeQuery, exact: lastSubmittedExact })}
      >
        Load more types
      </Button>
    {/if}
  {:else if typesHasRun && !typesError}
    <Alert.Root color="blue">
      <Alert.Title>No matching types</Alert.Title>
      <Alert.Description>Try a broader substring or toggle Exact OFF.</Alert.Description>
    </Alert.Root>
  {/if}
</div>
