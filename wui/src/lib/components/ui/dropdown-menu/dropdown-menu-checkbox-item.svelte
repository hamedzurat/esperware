<script lang="ts">
  import { cn, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { getContext, type Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    checked = $bindable(false),
    indeterminate = $bindable(false),
    class: className,
    children: childrenProp,
    ...restProps
  }: WithoutChildrenOrChild<DropdownMenuPrimitive.CheckboxItemProps> & {
    children?: Snippet;
  } = $props();

  const getColor = getContext<() => string>('dropdownMenuColor');
</script>

<DropdownMenuPrimitive.CheckboxItem
  bind:ref
  bind:checked
  bind:indeterminate
  data-slot="dropdown-menu-checkbox-item"
  data-highlighted-color={getColor()}
  class={cn(
    'group neoretro-highlighted data-disabled:neoretro-disable relative flex items-center gap-2 rounded py-1.5 ps-8 pe-2 text-sm outline-hidden select-none',
    className,
  )}
  {...restProps}
>
  {#snippet children({ checked, indeterminate })}
    <span
      class={cn(
        'neoretro-border group-data-highlighted:border-clr-highlighted group-data-[state=open]:border-clr-highlighted pointer-events-none absolute inset-s-2 flex size-4 shrink-0 items-center justify-center rounded-sm transition-none',
        checked && !indeterminate ? 'neoretro-clr' : 'bg-transparent',
      )}
      data-color={checked && !indeterminate ? 'black' : getColor()}
    >
      {#if indeterminate}
        <div class="bg-border h-1 w-2 group-data-highlighted:bg-current"></div>
      {/if}
    </span>
    {@render childrenProp?.()}
  {/snippet}
</DropdownMenuPrimitive.CheckboxItem>
