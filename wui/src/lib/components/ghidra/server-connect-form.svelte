<script lang="ts">
  import Columns2Icon from '@lucide/svelte/icons/columns-2';
  import ExternalLinkIcon from '@lucide/svelte/icons/external-link';
  import PlugIcon from '@lucide/svelte/icons/plug';
  import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
  import ShieldAlertIcon from '@lucide/svelte/icons/shield-alert';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';

  let {
    target = $bindable(''),
    token = $bindable(''),
    error = null,
    compact = false,
    showRetry = false,
    showSplit = false,
    connectLabel = 'Connect',
    onConnect,
    onSplit = undefined,
    onOpenTab,
    onRetry = undefined,
  }: {
    target?: string;
    token?: string;
    error?: string | null;
    compact?: boolean;
    showRetry?: boolean;
    showSplit?: boolean;
    connectLabel?: string;
    onConnect: (raw: string, token: string) => void;
    onSplit?: (raw: string, token: string) => void;
    onOpenTab: (raw: string) => void;
    onRetry?: () => void;
  } = $props();

  const uid = $props.id();
  const targetId = `${uid}-target`;
  const tokenId = `${uid}-token`;
</script>

<form
  class={compact ? 'grid grid-cols-1 gap-3 md:grid-cols-[1fr_200px_auto] md:items-end' : 'space-y-3'}
  onsubmit={(e) => {
    e.preventDefault();
    onConnect(target, token);
  }}
>
  <Field.Field>
    <Field.Label for={targetId}>Server Port or URL</Field.Label>
    <Input id={targetId} color="white" bind:value={target} placeholder="43299 or http://127.0.0.1:8765" />
  </Field.Field>

  <Field.Field>
    <Field.Label for={tokenId}>Bearer Token (optional)</Field.Label>
    <Input
      id={tokenId}
      color="white"
      type="password"
      autocomplete="off"
      bind:value={token}
      placeholder="RO or RW token"
    />
  </Field.Field>

  <div class="flex flex-wrap items-center gap-2">
    <Button type="submit" color="green" size={compact ? 'sm' : 'default'}>
      <PlugIcon />
      {connectLabel}
    </Button>

    {#if showSplit && onSplit}
      <Button type="button" color="magenta" size={compact ? 'sm' : 'default'} onclick={() => onSplit(target, token)}>
        <Columns2Icon />
        Split
      </Button>
    {/if}

    <Button type="button" color="blue" size={compact ? 'sm' : 'default'} onclick={() => onOpenTab(target)}>
      <ExternalLinkIcon />
      {compact ? 'Tab' : 'Open in new tab'}
    </Button>

    {#if showRetry && onRetry}
      <Button type="button" color="yellow" size={compact ? 'sm' : 'default'} onclick={onRetry}>
        <RefreshCwIcon />
        Retry
      </Button>
    {/if}
  </div>
</form>

{#if error}
  <Alert.Root color="red" class="mt-3">
    <ShieldAlertIcon />
    <Alert.Title>Invalid server</Alert.Title>
    <Alert.Description>{error}</Alert.Description>
  </Alert.Root>
{/if}
