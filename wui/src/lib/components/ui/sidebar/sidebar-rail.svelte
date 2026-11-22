<script lang="ts">
  import { cn, type WithElementRef } from '#lib/utils.ts';
  import type { HTMLAttributes } from 'svelte/elements';

  import { useSidebar } from './context.svelte.ts';

  let {
    ref = $bindable(null),
    class: className,
    children,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLButtonElement>, HTMLButtonElement> = $props();

  const sidebar = useSidebar();
</script>

<button
  bind:this={ref}
  data-sidebar="rail"
  data-slot="sidebar-rail"
  aria-label="Toggle Sidebar"
  tabIndex={-1}
  onclick={sidebar.toggle}
  title="Toggle Sidebar"
  class={cn(
    'hover:after:neoretro-border absolute inset-y-0 z-20 hidden w-4 -translate-x-1/2 transition-all ease-linear group-data-[collapsible=offcanvas]:translate-x-0 group-data-[side=left]:-right-4 group-data-[side=right]:left-0 after:absolute after:inset-y-0 after:left-[calc(1/2*100%-1px)] after:w-[2px] group-data-[collapsible=offcanvas]:after:left-full in-data-[side=left]:cursor-w-resize in-data-[side=right]:cursor-e-resize sm:flex [[data-side=left][data-collapsible=offcanvas]_&]:-right-2 [[data-side=left][data-state=collapsed]_&]:cursor-e-resize [[data-side=right][data-collapsible=offcanvas]_&]:-left-2 [[data-side=right][data-state=collapsed]_&]:cursor-w-resize',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</button>
