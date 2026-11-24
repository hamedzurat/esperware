<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import {
    formatBytes,
    isExternalSegmentAddress,
    sameAddress,
    type FunctionRow,
    type SegmentInfo,
  } from '#lib/ghidra-api.ts';

  let {
    functions,
    totalFunctions,
    selectedTarget,
    segments = [],
    filterText = $bindable(''),
    sortBy,
    listLoading,
    listError,
    hasMore,
    onFilterInput,
    onSortChange,
    onSelect,
    onLoadMore,
  }: {
    functions: FunctionRow[];
    totalFunctions: number;
    selectedTarget: string | null;
    segments?: SegmentInfo[];
    filterText?: string;
    sortBy: 'address' | 'name' | 'size';
    listLoading: boolean;
    listError: string | null;
    hasMore: boolean;
    onFilterInput: () => void;
    onSortChange: (sort: 'address' | 'name' | 'size') => void;
    onSelect: (addr: string) => void;
    onLoadMore: () => void;
  } = $props();

  const filterInputId = $props.id();
</script>

<Card.Root color="bright-black" class="min-w-0">
  <Card.Header class="space-y-3">
    <Card.Title class="flex items-center justify-between gap-2 text-lg">
      <span>Functions</span>
      <Badge color="yellow">{totalFunctions}</Badge>
    </Card.Title>

    <Field.Field>
      <Field.Label for={filterInputId}>Filter</Field.Label>
      <Input
        id={filterInputId}
        color="white"
        bind:value={filterText}
        placeholder="Name or address..."
        oninput={onFilterInput}
      />
    </Field.Field>

    <ButtonGroup.Root class="w-full" aria-label="Sort functions">
      {#each ['address', 'name', 'size'] as const as opt (opt)}
        <Button
          color={sortBy === opt ? 'cyan' : 'white'}
          size="sm"
          class="flex-1 capitalize"
          aria-pressed={sortBy === opt}
          onclick={() => onSortChange(opt)}
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

    <div class="max-h-[min(65vh,640px)] space-y-2 overflow-y-auto p-1">
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
            <button {...props} type="button" onclick={() => onSelect(fn.address)}>
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

    {#if hasMore}
      <Button color="blue" size="sm" class="w-full" disabled={listLoading} onclick={onLoadMore}>
        Load more functions
      </Button>
    {/if}
  </Card.Content>
</Card.Root>
