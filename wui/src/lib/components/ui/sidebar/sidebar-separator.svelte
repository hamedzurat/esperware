<script lang="ts">
  import { Separator } from '#lib/components/ui/separator/index.ts';
  import { cn } from '#lib/utils.ts';
  import type { ComponentProps } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: ComponentProps<typeof Separator> = $props();
</script>

<Separator
  bind:ref
  data-slot="sidebar-separator"
  data-sidebar="separator"
  class={cn('bg-border -mx-1 my-1 h-px', className)}
  {...restProps}
/>
