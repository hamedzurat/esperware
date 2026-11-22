<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { NavigationMenu as NavigationMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: NavigationMenuPrimitive.IndicatorProps = $props();

  const getColor = getContext<() => string>('navigationMenuColor');
</script>

<NavigationMenuPrimitive.Indicator
  bind:ref
  data-slot="navigation-menu-indicator"
  class={cn('neoretro-border top-full z-1 flex h-1.5 items-end justify-center overflow-hidden', className)}
  {...restProps}
>
  <div
    data-color={getColor()}
    class={cn('neoretro-border neoretro-clr relative top-[60%] size-2 rotate-45 rounded-tl-sm')}
  ></div>
</NavigationMenuPrimitive.Indicator>
