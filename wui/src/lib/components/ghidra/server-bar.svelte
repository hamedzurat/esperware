<script lang="ts">
  import Columns2Icon from '@lucide/svelte/icons/columns-2';
  import ExternalLinkIcon from '@lucide/svelte/icons/external-link';
  import ServerIcon from '@lucide/svelte/icons/server';
  import XIcon from '@lucide/svelte/icons/x';
  import ServerConnectForm from '#lib/components/ghidra/server-connect-form.svelte';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import * as ButtonGroup from '#lib/components/ui/button-group/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Collapsible from '#lib/components/ui/collapsible/index.js';
  import { buildServerQuery, formatServerTag, normalizeTarget, type SavedServer } from '#lib/ghidra-api.ts';

  let {
    savedServers = [],
    activeUrls = [],
    activePaneLabel = 'pane 1',
    onConnectInActive,
    onOpenInSplit,
    onOpenInNewTab,
    onRemoveServer,
  }: {
    savedServers?: SavedServer[];
    activeUrls?: string[];
    activePaneLabel?: string;
    onConnectInActive: (raw: string, token?: string) => void;
    onOpenInSplit: (raw: string, token?: string) => void;
    onOpenInNewTab: (raw: string, onInvalid?: (msg: string) => void) => void;
    onRemoveServer: (baseUrl: string) => void;
  } = $props();

  let switcherOpen = $state(false);
  let footerTarget = $state('');
  let footerToken = $state('');
  let footerError = $state<string | null>(null);

  function validateTarget(raw: string): string | null {
    footerError = null;
    const trimmed = raw.trim();
    try {
      normalizeTarget(trimmed);
      return trimmed;
    } catch (error) {
      footerError = error instanceof Error ? error.message : 'Invalid server port or URL.';
      return null;
    }
  }
</script>

<Card.Root color="bright-black" class="py-3">
  <Card.Content class="space-y-3">
    <Collapsible.Root bind:open={switcherOpen}>
      <div class="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <Badge color="white">{activeUrls.length} active</Badge>
          <span>Target pane: {activePaneLabel}</span>
          {#if savedServers.length > 0}
            <span>·</span>
            <span>{savedServers.length} saved</span>
          {/if}
        </div>

        <Collapsible.Trigger>
          {#snippet child({ props })}
            <Button {...props} color="yellow" size="sm">
              <ServerIcon />
              Switch / Add server
            </Button>
          {/snippet}
        </Collapsible.Trigger>
      </div>

      {#if savedServers.length > 0}
        <div class="flex flex-wrap items-center gap-2 pt-3">
          {#each savedServers as srv (srv.baseUrl)}
            {@const isOpen = activeUrls.includes(srv.baseUrl)}
            <ButtonGroup.Root>
              <Button color={isOpen ? 'cyan' : 'white'} size="sm" onclick={() => onConnectInActive(srv.raw)}>
                {srv.label ? `${srv.label} (${formatServerTag(srv.baseUrl)})` : formatServerTag(srv.baseUrl)}
              </Button>
              <Button
                color="magenta"
                size="icon-sm"
                aria-label={`Open ${srv.baseUrl} in split pane`}
                onclick={() => onOpenInSplit(srv.raw)}
              >
                <Columns2Icon />
              </Button>
              <Button
                color="blue"
                size="icon-sm"
                href={buildServerQuery(srv.raw)}
                target="_blank"
                rel="noopener"
                aria-label={`Open ${srv.baseUrl} in new tab`}
              >
                <ExternalLinkIcon />
              </Button>
              <Button
                color="red"
                size="icon-sm"
                aria-label={`Remove ${srv.baseUrl}`}
                onclick={() => onRemoveServer(srv.baseUrl)}
              >
                <XIcon />
              </Button>
            </ButtonGroup.Root>
          {/each}
        </div>
      {/if}

      <Collapsible.Content class="pt-3">
        <ServerConnectForm
          bind:target={footerTarget}
          bind:token={footerToken}
          error={footerError}
          compact
          showSplit
          connectLabel="Connect active"
          onConnect={(raw, token) => {
            const valid = validateTarget(raw);
            if (!valid) return;
            onConnectInActive(valid, token);
          }}
          onSplit={(raw, token) => {
            const valid = validateTarget(raw);
            if (!valid) return;
            onOpenInSplit(valid, token);
          }}
          onOpenTab={(raw) =>
            onOpenInNewTab(raw, (msg) => {
              footerError = msg;
            })}
        />
      </Collapsible.Content>
    </Collapsible.Root>
  </Card.Content>
</Card.Root>
