<script lang="ts">
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    class: className,
    color,
    children,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLElement>> & {
    color: 'black' | 'bright-black' | Color;
  } = $props();
</script>

<kbd
  bind:this={ref}
  data-slot="kbd"
  data-color={color}
  class={cn(
    'neoretro-border neoretro-clr in-data-[slot=tooltip-content]:bg-background/20 in-data-[slot=tooltip-content]:text-background dark:in-data-[slot=tooltip-content]:bg-background/10 pointer-events-none inline-flex h-5 w-fit min-w-5 items-center justify-center gap-1 rounded px-1 text-xs font-medium select-none [&_svg:not([class*="size-"])]:size-3',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</kbd>
