<script lang="ts">
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    class: className,
    color,
    noShadow = false,
    children,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLDivElement>> & {
    color: 'black' | 'bright-black' | Color;
    noShadow?: boolean;
  } = $props();
</script>

<div
  bind:this={ref}
  data-slot="card"
  data-color={color}
  class={cn(
    'neoretro-border neoretro-clr flex flex-col gap-4 rounded py-4',
    noShadow ? '' : 'neoretro-shadow',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</div>
