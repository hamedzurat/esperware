<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { NavigationMenu as NavigationMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: NavigationMenuPrimitive.LinkProps = $props();

  const getColor = getContext<() => string>('navigationMenuColor');
</script>

<NavigationMenuPrimitive.Link
  bind:ref
  data-slot="navigation-menu-link"
  data-hover-color={getColor()}
  class={cn(
    "neoretro-hover focus-visible:neoretro-focus data-[active=true]:neoretro-focus flex flex-col gap-1 rounded p-2 text-sm transition-all outline-none [&_svg:not([class*='size-'])]:size-4",
    className,
  )}
  {...restProps}
/>
