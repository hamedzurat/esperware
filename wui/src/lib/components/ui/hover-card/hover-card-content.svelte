<script lang="ts">
  import { cn, type Color } from '#lib/utils.ts';
  import { LinkPreview as HoverCardPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    class: className,
    color,
    align = 'center',
    sideOffset = 4,
    portalProps,
    ...restProps
  }: HoverCardPrimitive.ContentProps & {
    color: Color;
    portalProps?: HoverCardPrimitive.PortalProps;
  } = $props();
</script>

<HoverCardPrimitive.Portal {...portalProps}>
  <HoverCardPrimitive.Content
    bind:ref
    data-slot="hover-card-content"
    {align}
    {sideOffset}
    data-color={color}
    class={cn(
      'neoretro-shadow neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 w-64 origin-(--radix-hover-card-content-transform-origin) rounded p-4',
      className,
    )}
    {...restProps}
  />
</HoverCardPrimitive.Portal>
