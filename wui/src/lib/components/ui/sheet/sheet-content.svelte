<script lang="ts">
  import { cn, type Color, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { Dialog as SheetPrimitive } from 'bits-ui';
  import type { Snippet } from 'svelte';

  import SheetOverlay from './sheet-overlay.svelte';

  let {
    ref = $bindable(null),
    class: className,
    color,
    side = 'right',
    portalProps,
    children,
    ...restProps
  }: WithoutChildrenOrChild<SheetPrimitive.ContentProps> & {
    color: 'black' | 'bright-black' | Color;
    portalProps?: SheetPrimitive.PortalProps;
    side?: 'top' | 'right' | 'bottom' | 'left';
    children: Snippet;
  } = $props();
</script>

<SheetPrimitive.Portal {...portalProps}>
  <SheetOverlay />
  <SheetPrimitive.Content
    bind:ref
    data-slot="sheet-content"
    data-color={color}
    class={cn(
      'neoretro-shadow neoretro-border neoretro-clr data-[state=closed]:animate-out data-[state=open]:animate-in fixed z-50 flex flex-col gap-4 rounded transition duration-400 ease-in-out',
      side === 'top' &&
        'data-[state=closed]:slide-out-to-top data-[state=open]:slide-in-from-top inset-x-0 top-0 h-auto border-b',
      side === 'right' &&
        'data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right inset-y-0 right-0 h-full w-3/4 border-l sm:max-w-sm',
      side === 'bottom' &&
        'data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom inset-x-0 bottom-0 h-auto border-t',
      side === 'left' &&
        'data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left inset-y-0 left-0 h-full w-3/4 border-r sm:max-w-sm',
      className,
    )}
    {...restProps}
  >
    {@render children?.()}
  </SheetPrimitive.Content>
</SheetPrimitive.Portal>
