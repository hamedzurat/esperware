<script lang="ts">
  import { cn, type Color } from '#lib/utils.ts';
  import { Popover as PopoverPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    class: className,
    color,
    sideOffset = 4,
    align = 'center',
    portalProps,
    ...restProps
  }: PopoverPrimitive.ContentProps & {
    color: 'black' | 'bright-black' | Color;
    portalProps?: PopoverPrimitive.PortalProps;
  } = $props();
</script>

<PopoverPrimitive.Portal {...portalProps}>
  <PopoverPrimitive.Content
    bind:ref
    data-slot="popover-content"
    {sideOffset}
    {align}
    data-color={color}
    class={cn(
      'neoretro-shadow neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 mt-0.5 w-72 rounded p-4 outline-none',
      className,
    )}
    {...restProps}
  />
</PopoverPrimitive.Portal>
