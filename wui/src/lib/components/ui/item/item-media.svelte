<script lang="ts">
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    class: className,
    children,
    variant = 'default',
    color,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLDivElement>> & {
    variant?: 'default' | 'icon' | 'image';
    color: 'black' | 'bright-black' | Color;
  } = $props();
</script>

<div
  bind:this={ref}
  data-slot="item-media"
  data-variant={variant}
  data-color={color}
  class={cn(
    'flex shrink-0 items-center justify-center gap-2 *:pointer-events-none group-has-data-[slot=item-description]/item:translate-y-0.5 group-has-data-[slot=item-description]/item:self-start',
    variant === 'default' && 'bg-transparent',
    variant === 'icon' && '*:not([class*="size-"]):size-4 neoretro-border size-8 rounded',
    variant === 'image' && '*:is(img):size-full *:is(img):object-cover neoretro-border size-10 overflow-hidden rounded',
    color && 'neoretro-clr',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</div>
