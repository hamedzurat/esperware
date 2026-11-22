<script lang="ts">
  import { cn, type Color } from '#lib/utils.ts';
  import { Tooltip as TooltipPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    class: className,
    color,
    sideOffset = 0,
    side = 'top',
    children,
    arrowClasses,
    portalProps,
    ...restProps
  }: TooltipPrimitive.ContentProps & {
    color: 'black' | 'bright-black' | Color;
    arrowClasses?: string;
    portalProps?: TooltipPrimitive.PortalProps;
  } = $props();
</script>

<TooltipPrimitive.Portal {...portalProps}>
  <TooltipPrimitive.Content
    bind:ref
    data-slot="tooltip-content"
    {sideOffset}
    {side}
    data-color={color}
    class={cn(
      'neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 m-1 origin-(--radix-tooltip-content-transform-origin) overflow-hidden rounded px-3 py-1.5 text-sm',
      className,
    )}
    {...restProps}
  >
    {@render children?.()}
    <TooltipPrimitive.Arrow>
      {#snippet child({ props })}
        <div data-color={color} class={cn('z-50 rotate-45 rounded', 'neoretro-clr', arrowClasses)} {...props}></div>
      {/snippet}
    </TooltipPrimitive.Arrow>
  </TooltipPrimitive.Content>
</TooltipPrimitive.Portal>
