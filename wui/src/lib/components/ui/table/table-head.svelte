<script lang="ts">
  import { cn, type WithElementRef } from '#lib/utils.ts';
  import { getContext } from 'svelte';
  import type { HTMLThAttributes } from 'svelte/elements';

  let { ref = $bindable(null), class: className, children, ...restProps }: WithElementRef<HTMLThAttributes> = $props();

  const getHeaderColor = getContext<() => string>('tableHeaderColor');
</script>

<th
  bind:this={ref}
  data-slot="table-head"
  data-color={getHeaderColor()}
  class={cn(
    'neoretro-clr not-first:border-border h-12 px-4 text-left align-middle font-semibold not-first:border-l-2',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</th>
