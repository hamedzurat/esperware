<script lang="ts">
  import * as Alert from '#lib/components/ui/alert/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import { CodeBlock } from '#lib/components/ui/code-block/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import { formatRouteError, type GhidraClient, type MemoryFormat, type MemoryResponse } from '#lib/ghidra-api.ts';
  import { untrack } from 'svelte';

  let {
    client,
    active = false,
    initialAddr = '',
    initialSize = 64,
    initialFormat = 'hex',
    memoryRequest = null,
    onStateChange = undefined,
  }: {
    client: GhidraClient;
    active?: boolean;
    initialAddr?: string;
    initialSize?: number;
    initialFormat?: MemoryFormat;
    memoryRequest?: { addr: string; size?: number; seq: number } | null;
    onStateChange?: (addr: string, size: number, format: MemoryFormat) => void;
  } = $props();

  const uid = $props.id();
  const addrInputId = `${uid}-addr`;
  const sizeInputId = `${uid}-size`;

  let memAddress = $state(untrack(() => initialAddr));
  let memSize = $state(untrack(() => initialSize));
  let memFormat = $state<MemoryFormat>(untrack(() => initialFormat));
  let memResult = $state<MemoryResponse | null>(null);
  let memLoading = $state(false);
  let memError = $state<string | null>(null);

  let reqCtrl: AbortController | null = null;
  let memReqSeq = 0;
  let lastMemorySeq = 0;
  let didInitialAutoRead = false;

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

  async function readMemory() {
    const addr = memAddress.trim();
    if (!addr) {
      memError = 'Enter a memory address to inspect.';
      return;
    }
    reqCtrl?.abort();
    const ctrl = new AbortController();
    reqCtrl = ctrl;

    const req = ++memReqSeq;
    memLoading = true;
    memError = null;
    memResult = null;
    try {
      const parsed = Number(memSize);
      const clampedSize = Number.isFinite(parsed) && parsed >= 1 ? Math.min(4096, Math.floor(parsed)) : 64;
      memSize = clampedSize;
      const res = await client.memory({ address: addr, size: clampedSize, format: memFormat }, ctrl.signal);
      if (req !== memReqSeq || ctrl.signal.aborted) return;
      memResult = res;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      if (req === memReqSeq) memError = formatRouteError('/api/v1/memory', error);
    } finally {
      if (req === memReqSeq) memLoading = false;
    }
  }

  $effect(() => {
    const isActive = active;
    const req = memoryRequest;
    if (!isActive) return;
    untrack(() => {
      if (req && req.seq !== lastMemorySeq) {
        lastMemorySeq = req.seq;
        didInitialAutoRead = true;
        memAddress = req.addr;
        if (req.size !== undefined && Number.isFinite(req.size) && req.size >= 1) {
          memSize = Math.min(4096, Math.floor(req.size));
        }
        void readMemory();
        return;
      }
      if (!didInitialAutoRead) {
        didInitialAutoRead = true;
        if (memAddress.trim()) {
          void readMemory();
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
    const addr = memAddress;
    const size = Number(memSize) || 64;
    const format = memFormat;
    untrack(() => {
      onStateChange?.(addr, size, format);
    });
  });
</script>

<div class="space-y-4">
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
          <Field.Label for={addrInputId}>Address</Field.Label>
          <Input id={addrInputId} color="white" bind:value={memAddress} placeholder="0x401000 or 00401000" />
        </Field.Field>

        <Field.Field class="w-28">
          <Field.Label for={sizeInputId}>Bytes</Field.Label>
          <Input id={sizeInputId} color="white" type="number" min={1} max={4096} bind:value={memSize} />
        </Field.Field>

        <div class="space-y-2">
          <div class="font-mono text-xs font-bold">Format</div>
          <ButtonGroup.Root aria-label="Memory format">
            {#each ['hex', 'utf8', 'u32', 'u64'] as const as fmt (fmt)}
              <Button
                color={memFormat === fmt ? 'cyan' : 'white'}
                size="sm"
                aria-pressed={memFormat === fmt}
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
</div>
