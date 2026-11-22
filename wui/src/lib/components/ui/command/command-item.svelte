<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Command as CommandPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, ...restProps }: CommandPrimitive.ItemProps = $props();

  const getColor = getContext<() => string>('commandColor');
</script>

<CommandPrimitive.Item
  bind:ref
  data-slot="command-item"
  data-hover-color={getColor()}
  class={cn(
    "neoretro-focus neoretro-hover data-[disabled=true]:neoretro-disable relative flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm select-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
    className,
  )}
  {...restProps}
/>
