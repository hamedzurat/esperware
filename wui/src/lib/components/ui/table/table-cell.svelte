<script lang="ts">
  import { cn, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLTdAttributes } from 'svelte/elements';

  let { ref = $bindable(null), class: className, children, ...restProps }: WithElementRef<HTMLTdAttributes> = $props();
</script>

<td
  bind:this={ref}
  data-slot="table-cell"
  class={cn('not-first:neoretro-border-l p-4 align-top', className)}
  {...restProps}
>
  {@render children?.()}
</td>
