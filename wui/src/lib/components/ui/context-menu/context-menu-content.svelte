<script lang="ts">
  import { cn, type Color } from '#lib/utils.ts';
  import { ContextMenu as ContextMenuPrimitive } from 'bits-ui';
  import { setContext } from 'svelte';

  let {
    ref = $bindable(null),
    color,
    portalProps,
    class: className,
    ...restProps
  }: ContextMenuPrimitive.ContentProps & {
    color: 'black' | 'bright-black' | Color;
    portalProps?: ContextMenuPrimitive.PortalProps;
  } = $props();

  setContext('contextMenuColor', () => color);
</script>

<ContextMenuPrimitive.Portal {...portalProps}>
  <ContextMenuPrimitive.Content
    bind:ref
    data-slot="context-menu-content"
    data-color={color}
    class={cn(
      'neoretro-shadow neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 min-w-32 origin-(--radix-context-menu-content-transform-origin) overflow-hidden rounded p-1',
      className,
    )}
    {...restProps}
  />
</ContextMenuPrimitive.Portal>
