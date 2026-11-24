<script lang="ts">
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Table from '#lib/components/ui/table/index.js';
  import { isReadableAddress, type GlobalInfo, type SegmentInfo, type VariableInfo } from '#lib/ghidra-api.ts';

  let {
    variables = [],
    globals = [],
    segments = [],
    onOpenMemory,
  }: {
    variables?: VariableInfo[];
    globals?: GlobalInfo[];
    segments?: SegmentInfo[];
    onOpenMemory: (addr: string, size?: number) => void;
  } = $props();
</script>

{#if variables.length > 0}
  <Card.Root color="bright-black">
    <Card.Header>
      <Card.Title class="text-base">Variables ({variables.length})</Card.Title>
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
          {#each variables as v, idx (`${v.kind}-${v.name}-${idx}`)}
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

{#if globals.length > 0}
  <Card.Root color="bright-black">
    <Card.Header>
      <Card.Title class="text-base">Referenced Globals ({globals.length})</Card.Title>
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
          {#each globals as g (g.address)}
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
