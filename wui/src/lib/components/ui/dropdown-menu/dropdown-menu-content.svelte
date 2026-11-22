<script lang="ts">
  import { cn, type Color, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { setContext, type ComponentProps } from 'svelte';

  import DropdownMenuPortal from './dropdown-menu-portal.svelte';

  let {
    ref = $bindable(null),
    color,
    sideOffset = 4,
    portalProps,
    noShadow,
    preventScroll = false,
    class: className,
    ...restProps
  }: DropdownMenuPrimitive.ContentProps & {
    color: Color;
    portalProps?: WithoutChildrenOrChild<ComponentProps<typeof DropdownMenuPortal>>;
    noShadow?: boolean;
  } = $props();

  setContext('dropdownMenuColor', () => color);
</script>

<DropdownMenuPortal {...portalProps}>
  <DropdownMenuPrimitive.Content
    bind:ref
    data-slot="dropdown-menu-content"
    data-color={color}
    {sideOffset}
    {preventScroll}
    class={cn(
      'neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-end-2 data-[side=right]:slide-in-from-start-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 max-h-(--bits-dropdown-menu-content-available-height) min-w-32 origin-(--bits-dropdown-menu-content-transform-origin) overflow-x-hidden overflow-y-auto rounded p-1 outline-none',
      noShadow ? '' : 'neoretro-shadow',
      className,
    )}
    {...restProps}
  />
</DropdownMenuPortal>
