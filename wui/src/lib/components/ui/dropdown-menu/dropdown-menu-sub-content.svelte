<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: DropdownMenuPrimitive.SubContentProps = $props();

  const getColor = getContext<() => string>('dropdownMenuColor');
</script>

<DropdownMenuPrimitive.SubContent
  bind:ref
  data-slot="dropdown-menu-sub-content"
  data-color={getColor()}
  class={cn(
    'neoretro-shadow neoretro-border neoretro-clr data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-end-2 data-[side=right]:slide-in-from-start-2 data-[side=top]:slide-in-from-bottom-2 neoretro-animate z-50 m-1 min-w-32 origin-(--bits-dropdown-menu-content-transform-origin) overflow-hidden rounded p-1',
    className,
  )}
  {...restProps}
/>
