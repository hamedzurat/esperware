<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Menubar as MenubarPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: MenubarPrimitive.TriggerProps = $props();

  const getColor = getContext<() => string>('menubarColor');
</script>

<MenubarPrimitive.Trigger
  bind:ref
  data-slot="menubar-trigger"
  data-highlighted-color={getColor()}
  class={cn(
    'neoretro-focus neoretro-highlighted flex items-center rounded px-2 py-1 text-sm font-medium outline-hidden select-none',
    className,
  )}
  {...restProps}
/>
