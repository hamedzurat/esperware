<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { NavigationMenu as NavigationMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: NavigationMenuPrimitive.ViewportProps = $props();

  const getColor = getContext<() => string>('navigationMenuColor');
</script>

<div class={cn('absolute top-full left-0 isolate z-50 flex justify-center')}>
  <NavigationMenuPrimitive.Viewport
    bind:ref
    data-slot="navigation-menu-viewport"
    data-color={getColor()}
    class={cn(
      'neoretro-shadow neoretro-border neoretro-clr data-[state=closed]:animate-out data-[state=closed]:zoom-out-95 data-[state=open]:animate-in data-[state=open]:zoom-in-90 relative z-50 mt-1.5 h-(--bits-navigation-menu-viewport-height) w-full overflow-hidden rounded md:w-(--bits-navigation-menu-viewport-width)',
      className,
    )}
    {...restProps}
  />
</div>
