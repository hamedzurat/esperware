<script lang="ts">
  import { cn, type WithoutChild } from '#lib/utils.ts';
  import { Select as SelectPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    value,
    label,
    children: childrenProp,
    ...restProps
  }: WithoutChild<SelectPrimitive.ItemProps> = $props();

  const getColor = getContext<() => string>('selectColor');
</script>

<SelectPrimitive.Item
  bind:ref
  {value}
  data-slot="select-item"
  data-hover-color={getColor()}
  class={cn(
    "neoretro-focus neoretro-hover data-disabled:neoretro-disable relative flex w-full cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm outline-none select-none [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 *:[span]:last:flex *:[span]:last:items-center *:[span]:last:gap-2",
    className,
  )}
  {...restProps}
>
  {#snippet children({ selected, highlighted })}
    {#if childrenProp}
      {@render childrenProp({ selected, highlighted })}
    {:else}
      {label || value}
    {/if}
  {/snippet}
</SelectPrimitive.Item>
