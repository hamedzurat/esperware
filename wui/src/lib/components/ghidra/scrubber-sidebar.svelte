<script lang="ts">
  import CodeIcon from '@lucide/svelte/icons/code';
  import HistoryIcon from '@lucide/svelte/icons/history';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Item from '#lib/components/ui/item/index.js';
  import { sameAddress, type TouchedFunction, type VersionSummary } from '#lib/ghidra-api.ts';

  let {
    versionsDesc,
    touchedFunctions,
    sidebarTab,
    selectedVersion,
    activeFnAddr,
    onTabChange,
    onVersionClick,
    onFnClick,
  }: {
    versionsDesc: VersionSummary[];
    touchedFunctions: TouchedFunction[];
    sidebarTab: 'versions' | 'functions';
    selectedVersion: number;
    activeFnAddr: string;
    onTabChange: (tab: 'versions' | 'functions') => void;
    onVersionClick: (v: VersionSummary) => void;
    onFnClick: (address: string) => void;
  } = $props();
</script>

<Card.Root color="bright-black" class="min-w-0">
  <Card.Header>
    <Card.Title class="flex items-center justify-between gap-2 text-lg">
      <span>Timeline</span>
      <Badge color="yellow">{versionsDesc.length} ver</Badge>
    </Card.Title>
    <ButtonGroup.Root class="w-full" aria-label="Timeline view">
      <Button
        color={sidebarTab === 'versions' ? 'cyan' : 'white'}
        size="sm"
        class="flex-1"
        aria-pressed={sidebarTab === 'versions'}
        onclick={() => onTabChange('versions')}
      >
        <HistoryIcon />
        Versions
      </Button>
      <Button
        color={sidebarTab === 'functions' ? 'cyan' : 'white'}
        size="sm"
        class="flex-1"
        aria-pressed={sidebarTab === 'functions'}
        onclick={() => onTabChange('functions')}
      >
        <CodeIcon />
        Changed ({touchedFunctions.length})
      </Button>
    </ButtonGroup.Root>
  </Card.Header>

  <Card.Content>
    <div class="max-h-[min(65vh,640px)] space-y-2 overflow-y-auto p-1">
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
              <button {...props} type="button" onclick={() => onVersionClick(v)}>
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
              <button {...props} type="button" onclick={() => onFnClick(fn.address)}>
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
