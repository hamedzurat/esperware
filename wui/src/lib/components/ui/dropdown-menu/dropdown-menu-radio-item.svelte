<script lang="ts">
  import { cn, type WithoutChild } from '#lib/utils.ts';
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    children: childrenProp,
    ...restProps
  }: WithoutChild<DropdownMenuPrimitive.RadioItemProps> = $props();

  const getColor = getContext<() => string>('dropdownMenuColor');
</script>

<DropdownMenuPrimitive.RadioItem
  bind:ref
  data-slot="dropdown-menu-radio-item"
  data-highlighted-color={getColor()}
  class={cn(
    'group neoretro-highlighted data-disabled:neoretro-disable relative flex items-center gap-2 rounded py-1.5 ps-8 pe-2 text-sm outline-hidden select-none',
    className,
  )}
  {...restProps}
>
  {#snippet children({ checked })}
    <span
      class={cn(
        'neoretro-border group-data-highlighted:border-clr-highlighted group-data-[state=open]:border-clr-highlighted pointer-events-none absolute inset-s-2 flex size-4 shrink-0 items-center justify-center rounded-full transition-none',
        checked ? 'neoretro-clr' : 'bg-transparent',
      )}
      data-color={checked ? 'black' : getColor()}
    >
    </span>
    {@render childrenProp?.({ checked })}
  {/snippet}
</DropdownMenuPrimitive.RadioItem>
