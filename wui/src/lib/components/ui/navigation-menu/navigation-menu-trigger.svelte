<script lang="ts">
  import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
  import { cn } from '#lib/utils.ts';
  import { NavigationMenu as NavigationMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    children,
    ...restProps
  }: NavigationMenuPrimitive.TriggerProps = $props();

  const getColor = getContext<() => string>('navigationMenuColor');
</script>

<NavigationMenuPrimitive.Trigger
  bind:ref
  data-slot="navigation-menu-trigger"
  data-hover-color={getColor()}
  data-highlighted-color={getColor()}
  class={cn(
    'group group neoretro-focus neoretro-hover neoretro-highlighted disabled:neoretro-disable m-1 inline-flex h-8 w-max items-center justify-center rounded px-2 py-1 text-sm font-medium transition-[color,box-shadow] outline-none',
    className,
  )}
  {...restProps}
>
  {@render children?.()}

  <ChevronDownIcon
    class="relative top-px ml-1 size-4 transition duration-300 group-data-[state=open]:rotate-180"
    aria-hidden="true"
  />
</NavigationMenuPrimitive.Trigger>
