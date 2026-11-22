<script lang="ts">
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLOlAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    class: className,
    color,
    noShadow,
    children,
    ...restProps
  }: WithElementRef<HTMLOlAttributes> & {
    color: Color;
    noShadow?: boolean;
  } = $props();
</script>

<ol
  bind:this={ref}
  data-slot="breadcrumb-list"
  data-color={color}
  class={cn(
    'neoretro-border neoretro-clr flex list-none flex-wrap items-center gap-1.5 rounded px-2.5 py-0.5 wrap-break-word sm:gap-2.5',
    noShadow ? '' : 'neoretro-shadow',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</ol>
