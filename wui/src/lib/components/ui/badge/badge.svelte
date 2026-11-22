<script lang="ts">
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLAnchorAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    href,
    class: className,
    color,
    children,
    ...restProps
  }: WithElementRef<HTMLAnchorAttributes> & {
    color: 'black' | 'bright-black' | Color;
  } = $props();
</script>

<svelte:element
  this={href ? 'a' : 'span'}
  bind:this={ref}
  data-slot="badge"
  {href}
  data-color={color}
  class={cn(
    'neoretro-focus neoretro-border neoretro-clr inline-flex w-fit shrink-0 items-center justify-center gap-1 rounded px-2.5 py-0.5 text-xs whitespace-nowrap [&>svg]:pointer-events-none [&>svg]:size-3',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</svelte:element>
