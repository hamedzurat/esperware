<script lang="ts">
  import CopyButton from '#lib/components/copy-button.svelte';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Table from '#lib/components/ui/table/index.js';
  import {
    classifyEntryPoint,
    formatBytes,
    formatUptime,
    isSegmentReadable,
    type StatusResponse,
  } from '#lib/ghidra-api.ts';

  let {
    status,
    onInspectFunction,
    onOpenMemory,
  }: {
    status: StatusResponse;
    onInspectFunction: (target: string) => void;
    onOpenMemory: (addr: string, size?: number) => void;
  } = $props();
</script>

<div class="space-y-4">
  <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
    <Card.Root color="white">
      <Card.Header>
        <Card.Title class="text-base">Binary</Card.Title>
        <Card.Description class="font-mono break-all">{status.binary_name}</Card.Description>
      </Card.Header>
      <Card.Content class="space-y-2 font-mono text-xs">
        <div class="flex items-center justify-between gap-2">
          <span>Format</span>
          <Badge color="cyan">{status.format || 'unknown'}</Badge>
        </div>
        <div class="flex items-center justify-between gap-2">
          <span>Endian</span>
          <Badge color="yellow">{status.endian}</Badge>
        </div>
        <div class="flex items-center justify-between gap-2">
          <span>Ghidra</span>
          <span>{status.ghidra_version}</span>
        </div>
      </Card.Content>
    </Card.Root>

    <Card.Root color="white">
      <Card.Header>
        <Card.Title class="text-base">Architecture</Card.Title>
        <Card.Description class="font-mono">{status.language}</Card.Description>
      </Card.Header>
      <Card.Content class="space-y-2 font-mono text-xs">
        <div class="flex items-center justify-between gap-2">
          <span>Compiler</span>
          <Badge color="blue">{status.compiler}</Badge>
        </div>
        <div class="flex items-center justify-between gap-2">
          <span>Functions</span>
          <Badge color="green">{status.function_count}</Badge>
        </div>
        <div class="flex items-center justify-between gap-2">
          <span>Data Types</span>
          <Badge color="magenta">{status.type_count}</Badge>
        </div>
      </Card.Content>
    </Card.Root>

    <Card.Root color="white">
      <Card.Header>
        <Card.Title class="text-base">Session</Card.Title>
        <Card.Description class="font-mono">
          Version v{status.version} · up {formatUptime(status.uptime_ms)}
        </Card.Description>
      </Card.Header>
      <Card.Content class="space-y-2 font-mono text-xs">
        <div class="flex items-center justify-between gap-2">
          <span class="truncate">SHA-256: {status.binary_sha256.slice(0, 16)}...</span>
          <CopyButton value={status.binary_sha256} variant="icon" color="yellow" size="sm" aria-label="Copy SHA-256" />
        </div>
        <div class="truncate">RW: {status.mcp_rw_url}</div>
        <div class="truncate">RO: {status.mcp_ro_url}</div>
      </Card.Content>
    </Card.Root>
  </div>

  <Card.Root color="bright-black">
    <Card.Header>
      <Card.Title class="text-base">Entry Points ({status.entry_points.length})</Card.Title>
    </Card.Header>
    <Card.Content>
      {#if status.entry_points.length === 0}
        <p class="font-mono text-xs">No external entry points reported.</p>
      {:else}
        <div class="flex flex-wrap gap-2">
          {#each status.entry_points as ep (ep)}
            {@const kind = classifyEntryPoint(ep, status.segments)}
            {#if kind === 'function'}
              <Button color="yellow" size="sm" onclick={() => onInspectFunction(ep)}>
                @{ep}
              </Button>
            {:else if kind === 'data'}
              <Button color="cyan" size="sm" onclick={() => onOpenMemory(ep)}>
                @{ep} · data
              </Button>
            {:else}
              <Badge color="white">@{ep} · uninit</Badge>
            {/if}
          {/each}
        </div>
      {/if}
    </Card.Content>
  </Card.Root>

  <Card.Root color="bright-black">
    <Card.Header>
      <Card.Title class="text-base">Memory Segments ({status.segments.length})</Card.Title>
    </Card.Header>
    <Card.Content>
      <Table.Root headerColor="blue" rowColor="white">
        <Table.Header>
          <Table.Row>
            <Table.Head>Name</Table.Head>
            <Table.Head>Start</Table.Head>
            <Table.Head>End</Table.Head>
            <Table.Head>Size</Table.Head>
            <Table.Head>Perms</Table.Head>
            <Table.Head>Memory</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {#each status.segments as seg (`${seg.name}-${seg.start}`)}
            {@const readable = isSegmentReadable(seg)}
            <Table.Row>
              <Table.Cell class="font-mono text-xs font-bold">{seg.name}</Table.Cell>
              <Table.Cell class="font-mono text-xs">{seg.start}</Table.Cell>
              <Table.Cell class="font-mono text-xs">{seg.end}</Table.Cell>
              <Table.Cell class="font-mono text-xs">{formatBytes(seg.size)}</Table.Cell>
              <Table.Cell>
                <div class="flex items-center gap-1 font-mono text-xs">
                  <Badge
                    color={seg.read ? 'green' : 'bright-black'}
                    aria-label={seg.read ? 'Readable' : 'Not readable'}
                  >
                    {seg.read ? 'R' : '-'}
                  </Badge>
                  <Badge
                    color={seg.write ? 'yellow' : 'bright-black'}
                    aria-label={seg.write ? 'Writable' : 'Not writable'}
                  >
                    {seg.write ? 'W' : '-'}
                  </Badge>
                  <Badge
                    color={seg.execute ? 'red' : 'bright-black'}
                    aria-label={seg.execute ? 'Executable' : 'Not executable'}
                  >
                    {seg.execute ? 'X' : '-'}
                  </Badge>
                </div>
              </Table.Cell>
              <Table.Cell>
                {#if readable}
                  <Button
                    color="cyan"
                    size="sm"
                    onclick={() => onOpenMemory(seg.start, Math.min(64, Math.max(1, seg.size)))}
                  >
                    Read bytes
                  </Button>
                {:else}
                  <Badge color="bright-black">{seg.external || seg.name === 'EXTERNAL' ? 'external' : 'uninit'}</Badge>
                {/if}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </Card.Content>
  </Card.Root>
</div>
