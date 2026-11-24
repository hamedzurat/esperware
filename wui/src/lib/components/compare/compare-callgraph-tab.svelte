<script lang="ts">
  import ZoomInIcon from '@lucide/svelte/icons/zoom-in';
  import ZoomOutIcon from '@lucide/svelte/icons/zoom-out';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import * as Table from '#lib/components/ui/table/index.js';
  import {
    alignCallgraphEdges,
    buildCallgraphLayout,
    getSnapshotPaletteEntry,
    type CallgraphEdgeStatus,
    type CallgraphNodeStatus,
    type FunctionCompareRow,
    type LoadedSnapshot,
  } from '#lib/snapshot-compare.ts';
  import { neoretroColors } from '#lib/utils.ts';

  let {
    snapshots,
    baselineIndex,
    functionRows,
    onOpenFunction,
  }: {
    snapshots: LoadedSnapshot[];
    baselineIndex: number;
    functionRows: FunctionCompareRow[];
    onOpenFunction: (offset: string) => void;
  } = $props();

  const uid = $props.id();

  let includeData = $state(true);
  let onlyMissing = $state(false);
  let focusNodeId = $state<string | null>(null);
  let zoom = $state(1);
  let kindFilter = $state<'all' | 'call' | 'data' | 'string'>('all');
  let searchQuery = $state('');
  let showAllEdges = $state(false);

  const safeBaselineIndex = $derived(baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0);

  const edgeRows = $derived(alignCallgraphEdges(snapshots));

  const layout = $derived(
    buildCallgraphLayout(snapshots, edgeRows, functionRows, {
      baselineIndex: safeBaselineIndex,
      includeData,
      onlyMissing,
      focusNodeId,
      maxNodes: 48,
    }),
  );

  const selectedNode = $derived(focusNodeId ? (layout.nodes.find((n) => n.id === focusNodeId) ?? null) : null);

  function nodeColors(status: CallgraphNodeStatus) {
    if (status === 'added') {
      return { fill: neoretroColors.green, text: neoretroColors.onGreen, badge: 'green' as const };
    }
    if (status === 'removed') {
      return { fill: neoretroColors.red, text: neoretroColors.onRed, badge: 'red' as const };
    }
    if (status === 'renamed') {
      return { fill: neoretroColors.yellow, text: neoretroColors.onYellow, badge: 'yellow' as const };
    }
    return { fill: neoretroColors.white, text: neoretroColors.onWhite, badge: 'cyan' as const };
  }

  function edgeStrokeColor(status: CallgraphEdgeStatus): string {
    if (status === 'added') return neoretroColors.green;
    if (status === 'removed') return neoretroColors.red;
    return neoretroColors.foreground;
  }

  function markerRef(status: CallgraphEdgeStatus): string {
    return `url(#${uid}-arrow-${status})`;
  }

  function truncateSvgLabel(text: string, maxLen = 26): string {
    if (text.length <= maxLen) return text;
    return `${text.slice(0, maxLen - 1)}…`;
  }

  const filteredEdgeRows = $derived.by(() => {
    const q = searchQuery.trim().toLowerCase();
    return edgeRows.filter((row) => {
      if (kindFilter !== 'all' && row.kind !== kindFilter) return false;
      if (onlyMissing && row.status !== 'missing') return false;
      if (focusNodeId && row.fromKey !== focusNodeId && row.toKey !== focusNodeId) return false;
      if (!q) return true;
      if (row.fromKey.toLowerCase().includes(q) || row.toKey.toLowerCase().includes(q)) return true;
      return row.slots.some((s) => s && (s.fromName.toLowerCase().includes(q) || s.toName.toLowerCase().includes(q)));
    });
  });

  const visibleEdgeRows = $derived(showAllEdges ? filteredEdgeRows : filteredEdgeRows.slice(0, 200));

  function toggleNodeFocus(id: string) {
    focusNodeId = focusNodeId === id ? null : id;
  }
</script>

<div class="space-y-4">
  <Card.Root color="bright-black" class="min-w-0">
    <Card.Content class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <ButtonGroup.Root aria-label="Callgraph edge types">
          <Button
            color={!includeData ? 'cyan' : 'white'}
            size="sm"
            aria-pressed={!includeData}
            onclick={() => (includeData = false)}
          >
            Calls only
          </Button>
          <Button
            color={includeData ? 'cyan' : 'white'}
            size="sm"
            aria-pressed={includeData}
            onclick={() => (includeData = true)}
          >
            + Data &amp; Strings
          </Button>
        </ButtonGroup.Root>

        <Button
          color={onlyMissing ? 'red' : 'white'}
          size="sm"
          aria-pressed={onlyMissing}
          onclick={() => (onlyMissing = !onlyMissing)}
        >
          {onlyMissing ? 'Added / Missing edges only' : 'All edges'}
        </Button>

        {#if focusNodeId}
          <Button color="magenta" size="sm" onclick={() => (focusNodeId = null)}>
            Clear focus (@{focusNodeId})
          </Button>
        {/if}

        {#if layout.truncated}
          <Badge color="yellow">Showing {layout.nodes.length}/{layout.totalNodes} nodes</Badge>
        {/if}
      </div>

      <ButtonGroup.Root aria-label="Graph zoom">
        <Button
          color="white"
          size="sm"
          disabled={zoom <= 0.5}
          aria-label="Zoom out"
          onclick={() => (zoom = Math.max(0.5, Number((zoom - 0.15).toFixed(2))))}
        >
          <ZoomOutIcon />
        </Button>
        <Button color="white" size="sm" onclick={() => (zoom = 1)}>
          {Math.round(zoom * 100)}%
        </Button>
        <Button
          color="white"
          size="sm"
          disabled={zoom >= 1.8}
          aria-label="Zoom in"
          onclick={() => (zoom = Math.min(1.8, Number((zoom + 0.15).toFixed(2))))}
        >
          <ZoomInIcon />
        </Button>
      </ButtonGroup.Root>
    </Card.Content>
  </Card.Root>

  <Card.Root color="white" class="min-w-0">
    <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2">
      <Card.Title class="font-mono text-sm">
        Callgraph Diff Map ({layout.nodes.length} nodes · {layout.edges.length} edges)
      </Card.Title>
      <div class="flex flex-wrap items-center gap-1.5">
        <Badge color="white">Same</Badge>
        <Badge color="yellow">Renamed</Badge>
        <Badge color="green">Added vs base</Badge>
        <Badge color="red">Missing vs base</Badge>
      </div>
    </Card.Header>

    <Card.Content class="space-y-3">
      {#if layout.nodes.length > 0}
        <div class="neoretro-border bg-background max-h-[min(68vh,680px)] w-full overflow-auto rounded p-2">
          <svg
            width={Math.round(layout.width * zoom)}
            height={Math.round(layout.height * zoom)}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            role="img"
            aria-label="Interactive callgraph comparison diagram"
          >
            <defs>
              <marker
                id={`${uid}-arrow-same`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill={neoretroColors.foreground} />
              </marker>
              <marker
                id={`${uid}-arrow-added`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill={neoretroColors.green} />
              </marker>
              <marker
                id={`${uid}-arrow-removed`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill={neoretroColors.red} />
              </marker>
            </defs>

            {#each layout.edges as edge (edge.key)}
              {@const stroke = edgeStrokeColor(edge.status)}
              <g>
                <path
                  d={edge.path}
                  fill="none"
                  {stroke}
                  stroke-width={edge.status === 'same' ? 1.8 : 2.5}
                  stroke-dasharray={edge.kind === 'call' ? undefined : '5 4'}
                  marker-end={markerRef(edge.status)}
                />
                {#if edge.totalCount > 1}
                  <rect
                    x={edge.labelX - 13}
                    y={edge.labelY - 9}
                    width="26"
                    height="18"
                    rx="3"
                    fill={neoretroColors.white}
                    stroke={neoretroColors.border}
                    stroke-width="1.5"
                  />
                  <text
                    x={edge.labelX}
                    y={edge.labelY + 4}
                    text-anchor="middle"
                    fill={neoretroColors.onWhite}
                    font-size="10"
                    font-family="monospace"
                    font-weight="700"
                  >
                    ×{edge.totalCount}
                  </text>
                {/if}
                <title>{`${edge.fromId} -> ${edge.toId} (${edge.kind}, ${edge.status})`}</title>
              </g>
            {/each}

            {#each layout.nodes as node (node.id)}
              {@const colors = nodeColors(node.status)}
              {@const isFocused = focusNodeId === node.id}
              <g
                role="button"
                tabindex="0"
                aria-label={`${node.sublabel} ${node.label} (${node.status})`}
                class="cursor-pointer"
                onclick={() => toggleNodeFocus(node.id)}
                onkeydown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleNodeFocus(node.id);
                  }
                }}
              >
                <rect
                  x={node.x + 3}
                  y={node.y + 3}
                  width={node.width}
                  height={node.height}
                  rx="4"
                  fill={neoretroColors.border}
                />
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.width}
                  height={node.height}
                  rx="4"
                  fill={colors.fill}
                  stroke={neoretroColors.border}
                  stroke-width={isFocused ? 3.5 : 2}
                />
                <text
                  x={node.x + 10}
                  y={node.y + 20}
                  fill={colors.text}
                  font-size="11"
                  font-family="monospace"
                  font-weight="700"
                >
                  {truncateSvgLabel(node.sublabel, 14)} · {node.status.toUpperCase()}
                </text>
                <text
                  x={node.x + 10}
                  y={node.y + 40}
                  fill={colors.text}
                  font-size="12"
                  font-family="monospace"
                  font-weight="700"
                >
                  {truncateSvgLabel(node.label, 25)}
                </text>
                <title>
                  {snapshots.map((s, idx) => `${s.label}: ${node.names[idx] ?? '(missing)'}`).join('\n')}
                </title>
              </g>
            {/each}
          </svg>
        </div>

        {#if selectedNode}
          <Card.Root color="bright-black" noShadow>
            <Card.Content class="flex flex-wrap items-center justify-between gap-3 pt-4">
              <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
                <Badge color={nodeColors(selectedNode.status).badge}>{selectedNode.status}</Badge>
                <span class="font-bold">{selectedNode.sublabel}</span>
                {#each snapshots as snap, idx (snap.id)}
                  <Badge color={getSnapshotPaletteEntry(idx).color}>
                    {snap.label}: {selectedNode.names[idx] ?? 'missing'}
                  </Badge>
                {/each}
              </div>

              {#if selectedNode.entryOffset}
                <Button color="cyan" size="sm" onclick={() => onOpenFunction(selectedNode.entryOffset!)}>
                  Inspect in Functions
                </Button>
              {/if}
            </Card.Content>
          </Card.Root>
        {:else}
          <p class="font-mono text-xs">Click any node in the graph to isolate its 1-hop neighborhood and edges.</p>
        {/if}
      {:else}
        <Alert.Root color="blue" noShadow>
          <Alert.Title>No graph edges match filter</Alert.Title>
          <Alert.Description>Try toggling “All edges” or including Data &amp; Strings.</Alert.Description>
        </Alert.Root>
      {/if}
    </Card.Content>
  </Card.Root>

  <Card.Root color="bright-black" class="min-w-0">
    <Card.Content class="flex flex-wrap items-end justify-between gap-3">
      <div class="flex flex-wrap gap-1.5">
        {#each ['all', 'call', 'data', 'string'] as const as kind (kind)}
          <Button
            color={kindFilter === kind ? 'magenta' : 'white'}
            size="sm"
            aria-pressed={kindFilter === kind}
            onclick={() => {
              kindFilter = kind;
              showAllEdges = false;
            }}
          >
            {kind}
          </Button>
        {/each}
      </div>

      <Field.Field class="min-w-56 flex-1 sm:max-w-xs">
        <Field.Label for={`${uid}-edge-search`}>Filter edges</Field.Label>
        <Input
          id={`${uid}-edge-search`}
          color="white"
          bind:value={searchQuery}
          placeholder="Caller, callee, or offset..."
        />
      </Field.Field>
    </Card.Content>
  </Card.Root>

  {#if visibleEdgeRows.length > 0}
    <Table.Root headerColor="magenta" rowColor="white">
      <Table.Header>
        <Table.Row>
          <Table.Head>Edge Key</Table.Head>
          <Table.Head>Kind</Table.Head>
          <Table.Head>Status</Table.Head>
          {#each snapshots as snap, idx (snap.id)}
            <Table.Head>
              <Badge color={getSnapshotPaletteEntry(idx).color}>{snap.label}</Badge>
            </Table.Head>
          {/each}
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each visibleEdgeRows as row (row.key)}
          <Table.Row>
            <Table.Cell class="font-mono text-xs whitespace-nowrap">
              {row.fromKey} → {row.toKey}
            </Table.Cell>
            <Table.Cell>
              <Badge color={row.kind === 'call' ? 'cyan' : row.kind === 'string' ? 'green' : 'yellow'}>
                {row.kind}
              </Badge>
            </Table.Cell>
            <Table.Cell class="font-mono text-xs">
              {#if row.status === 'identical'}
                <Badge color="green">identical</Badge>
              {:else if row.status === 'missing'}
                <Badge color="red">missing</Badge>
              {:else}
                <span>—</span>
              {/if}
            </Table.Cell>
            {#each row.slots as slot, idx (snapshots[idx]?.id ?? idx)}
              <Table.Cell class="font-mono text-xs break-all">
                {#if slot}
                  <span class="font-bold">{slot.fromName}</span>
                  <span> → </span>
                  <span class="font-bold">{slot.toName}</span>
                  {#if slot.count > 1}
                    <Badge color="bright-black" class="ml-1">×{slot.count}</Badge>
                  {/if}
                {:else}
                  <span>-</span>
                {/if}
              </Table.Cell>
            {/each}
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>

    {#if !showAllEdges && filteredEdgeRows.length > 200}
      <Button color="blue" size="sm" onclick={() => (showAllEdges = true)}>
        Show all {filteredEdgeRows.length} edges
      </Button>
    {/if}
  {/if}
</div>
