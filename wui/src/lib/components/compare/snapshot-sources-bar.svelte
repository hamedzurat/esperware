<script lang="ts">
  import ArrowLeftRightIcon from '@lucide/svelte/icons/arrow-left-right';
  import FolderOpenIcon from '@lucide/svelte/icons/folder-open';
  import PlusIcon from '@lucide/svelte/icons/plus';
  import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
  import Trash2Icon from '@lucide/svelte/icons/trash-2';
  import * as Alert from '#lib/components/ui/alert/index.js';
  import { Badge } from '#lib/components/ui/badge/index.js';
  import { Button } from '#lib/components/ui/button/index.js';
  import * as Card from '#lib/components/ui/card/index.js';
  import * as Field from '#lib/components/ui/field/index.js';
  import { Input } from '#lib/components/ui/input/index.js';
  import Spinner from '#lib/components/ui/spinner/spinner.svelte';
  import { getSnapshotPaletteEntry, type SnapshotSlotConfig } from '#lib/snapshot-compare.ts';

  let {
    slots,
    baselineIndex,
    busy,
    onUpdateLabel,
    onUpdatePath,
    onAddSlot,
    onRemoveSlot,
    onSelectBaseline,
    onLoadSlotPath,
    onLoadSlotFolder,
    onLoadAll,
    onSwapFirstTwo,
  }: {
    slots: SnapshotSlotConfig[];
    baselineIndex: number;
    busy: boolean;
    onUpdateLabel: (id: string, label: string) => void;
    onUpdatePath: (id: string, path: string) => void;
    onAddSlot: () => void;
    onRemoveSlot: (id: string) => void;
    onSelectBaseline: (idx: number) => void;
    onLoadSlotPath: (id: string) => void;
    onLoadSlotFolder: (id: string, files: FileList) => void;
    onLoadAll: () => void;
    onSwapFirstTwo: () => void;
  } = $props();

  const uid = $props.id();
  let folderInputs: Array<HTMLInputElement | null> = [];
  const dirPickerAttrs = { webkitdirectory: '', directory: '' } as Record<string, string>;

  const gridClass = $derived(
    slots.length >= 3
      ? 'grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3'
      : 'grid grid-cols-1 gap-4 md:grid-cols-2',
  );
</script>

<Card.Root color="white" class="min-w-0">
  <Card.Header class="flex flex-wrap items-center justify-between gap-3">
    <div class="space-y-1">
      <Card.Title class="font-mono text-base">Snapshot Sources ({slots.length})</Card.Title>
      <p class="font-mono text-xs">
        Enter exported snapshot directory paths (e.g. <code>export_layout_version: 2</code>) or pick folders from disk.
      </p>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      {#if slots.length >= 2}
        <Button color="white" size="sm" disabled={busy} onclick={onSwapFirstTwo}>
          <ArrowLeftRightIcon />
          Swap A ↔ B
        </Button>
      {/if}
      <Button color="green" size="sm" disabled={busy} onclick={onAddSlot}>
        <PlusIcon />
        Add snapshot
      </Button>
      <Button color="cyan" size="sm" disabled={busy} onclick={onLoadAll}>
        {#if busy}
          <Spinner color="white" />
        {:else}
          <RefreshCwIcon />
        {/if}
        Load all
      </Button>
    </div>
  </Card.Header>

  <Card.Content class={gridClass}>
    {#each slots as slot, idx (slot.id)}
      {@const palette = getSnapshotPaletteEntry(idx)}
      {@const isBaseline = idx === baselineIndex}
      <Card.Root color="bright-black" noShadow class="min-w-0">
        <Card.Header class="flex flex-row flex-wrap items-center justify-between gap-2 pb-1">
          <div class="flex flex-wrap items-center gap-2">
            <Badge color={palette.color}>#{idx + 1}</Badge>
            <Button
              color={isBaseline ? 'yellow' : 'white'}
              size="sm"
              aria-pressed={isBaseline}
              onclick={() => onSelectBaseline(idx)}
            >
              {isBaseline ? 'Baseline' : 'Set base'}
            </Button>
            {#if slot.status === 'ready' && slot.snapshot}
              <Badge color="green">ready</Badge>
            {:else if slot.status === 'loading'}
              <Badge color="cyan">
                <Spinner color="white" />
                loading
              </Badge>
            {:else if slot.status === 'error'}
              <Badge color="red">error</Badge>
            {:else}
              <Badge color="white">idle</Badge>
            {/if}
          </div>

          {#if slots.length > 2}
            <Button
              color="red"
              size="icon-sm"
              aria-label={`Remove ${slot.label || `snapshot ${idx + 1}`}`}
              onclick={() => onRemoveSlot(slot.id)}
            >
              <Trash2Icon />
            </Button>
          {/if}
        </Card.Header>

        <Card.Content class="space-y-3">
          <Field.Field>
            <Field.Label for={`${uid}-label-${slot.id}`}>Label</Field.Label>
            <Input
              id={`${uid}-label-${slot.id}`}
              color="white"
              value={slot.label}
              placeholder={`Snapshot ${idx + 1}`}
              oninput={(e) => onUpdateLabel(slot.id, e.currentTarget.value)}
            />
          </Field.Field>

          <Field.Field>
            <Field.Label for={`${uid}-path-${slot.id}`}>Directory path</Field.Label>
            <div class="flex flex-wrap items-center gap-2 sm:flex-nowrap">
              <Input
                id={`${uid}-path-${slot.id}`}
                color="white"
                class="min-w-0 flex-1 font-mono text-xs"
                value={slot.path}
                placeholder="/abs/path/to/snapshot"
                oninput={(e) => onUpdatePath(slot.id, e.currentTarget.value)}
                onkeydown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    onLoadSlotPath(slot.id);
                  }
                }}
              />
              <Button
                color={palette.color}
                size="sm"
                disabled={slot.status === 'loading' || !slot.path.trim()}
                onclick={() => onLoadSlotPath(slot.id)}
              >
                Load
              </Button>
              <Button
                color="white"
                size="sm"
                disabled={slot.status === 'loading'}
                onclick={() => folderInputs[idx]?.click()}
              >
                <FolderOpenIcon />
                Folder
              </Button>
              <input
                bind:this={folderInputs[idx]}
                type="file"
                multiple
                class="hidden"
                {...dirPickerAttrs}
                onchange={(e) => {
                  const files = e.currentTarget.files;
                  if (files && files.length > 0) {
                    onLoadSlotFolder(slot.id, files);
                  }
                  e.currentTarget.value = '';
                }}
              />
            </div>
          </Field.Field>

          {#if slot.error}
            <Alert.Root color="red" noShadow>
              <Alert.Title>Load failed</Alert.Title>
              <Alert.Description class="font-mono text-xs break-all">{slot.error}</Alert.Description>
            </Alert.Root>
          {/if}
        </Card.Content>
      </Card.Root>
    {/each}
  </Card.Content>
</Card.Root>
