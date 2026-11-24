<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import * as Table from '#lib/components/ui/table/index.js';
  import {
    formatRouteError,
    isExternalSegmentAddress,
    isReadableAddress,
    type GhidraClient,
    type SegmentInfo,
    type XrefKind,
    type XrefRow,
  } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    functionAddress,
    currentVersion,
    segments = [],
    onSelectFunction,
    onOpenMemory,
  }: {
    client: GhidraClient;
    functionAddress: string;
    currentVersion: number;
    segments?: SegmentInfo[];
    onSelectFunction: (target: string) => void;
    onOpenMemory: (addr: string, size?: number) => void;
  } = $props();

  let xrefKind = $state<XrefKind>('all');
  let xrefRows = $state<XrefRow[]>([]);
  let xrefTotal = $state(0);
  let xrefCursor = $state<string | undefined>(undefined);
  let xrefsLoading = $state(false);
  let xrefsError = $state<string | null>(null);

  let reqCtrl: AbortController | null = null;
  let xrefReqSeq = 0;

  async function loadXrefs(target: string, kind: XrefKind, append = false) {
    reqCtrl?.abort();
    const ctrl = new AbortController();
    reqCtrl = ctrl;

    const req = ++xrefReqSeq;
    xrefsLoading = true;
    xrefsError = null;
    if (!append) {
      xrefRows = [];
      xrefTotal = 0;
      xrefCursor = undefined;
    }
    try {
      const res = await client.xrefs(
        {
          target,
          kind,
          cursor: append ? xrefCursor : undefined,
          limit: 100,
        },
        ctrl.signal,
      );
      if (req !== xrefReqSeq || ctrl.signal.aborted) return;
      xrefRows = append ? [...xrefRows, ...res.xrefs] : res.xrefs;
      xrefTotal = res.total;
      xrefCursor = res.next_cursor;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === xrefReqSeq) {
        xrefsError = formatRouteError('/api/v1/xrefs', error);
      }
    } finally {
      if (req === xrefReqSeq) {
        xrefsLoading = false;
      }
    }
  }

  $effect(() => {
    const addr = functionAddress;
    const ver = currentVersion;
    const kind = xrefKind;
    void ver;
    untrack(() => {
      void loadXrefs(addr, kind, false);
    });
  });

  $effect(() => {
    return () => {
      reqCtrl?.abort();
    };
  });
</script>

<Card.Root color="bright-black">
  <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2">
    <Card.Title class="text-base">Cross-references ({xrefTotal})</Card.Title>
    <ButtonGroup.Root aria-label="Xref filter">
      {#each ['all', 'callers', 'callees', 'to', 'from'] as const as kind (kind)}
        <Button
          color={xrefKind === kind ? 'yellow' : 'white'}
          size="sm"
          aria-pressed={xrefKind === kind}
          onclick={() => (xrefKind = kind)}
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
                    <Button color="cyan" size="sm" onclick={() => onSelectFunction(xr.address!)}>
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
                      onclick={() => onSelectFunction(xr.from_function_address ?? xr.from_address!)}
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
                  {@const isFnTarget = Boolean(xr.to_is_function || (xr.ref_type && /CALL|JUMP/i.test(xr.ref_type)))}
                  {@const fnTarget = xr.to_function_address ?? xr.to_address}
                  {#if isFnTarget && fnTarget && !isExternalSegmentAddress(fnTarget, segments) && !/^Stack\[/i.test(fnTarget)}
                    <Button color="cyan" size="sm" onclick={() => onSelectFunction(fnTarget)}>
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
          onclick={() => void loadXrefs(functionAddress, xrefKind, true)}
        >
          Load more xrefs
        </Button>
      {/if}
    {/if}
  </Card.Content>
</Card.Root>
