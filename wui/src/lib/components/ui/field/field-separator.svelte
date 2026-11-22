<script lang="ts">
  import { Separator } from '#lib/components/ui/separator/index.ts';
  import type { SeparatorProps } from '#lib/components/ui/separator/separator.svelte';
  import { cn } from '#lib/utils.ts';

  let { class: className, children, ...restProps }: SeparatorProps = $props();
</script>

{#if children}
  <Separator data-slot="field-separator" class={cn('neoretro-border -mx-1 my-1 h-px', className)} {...restProps}>
    {@render children()}
  </Separator>
{:else}
  <Separator data-slot="field-separator" class={cn('neoretro-border -mx-1 my-1 h-px', className)} {...restProps} />
{/if}
