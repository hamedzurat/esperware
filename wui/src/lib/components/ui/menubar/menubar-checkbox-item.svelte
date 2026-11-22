<script lang="ts">
  import { cn, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { Menubar as MenubarPrimitive } from 'bits-ui';
  import { getContext, type Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    checked = $bindable(false),
    indeterminate = $bindable(false),
    children: childrenProp,
    ...restProps
  }: WithoutChildrenOrChild<MenubarPrimitive.CheckboxItemProps> & {
    children?: Snippet;
  } = $props();

  const getColor = getContext<() => string>('menubarColor');
</script>

<MenubarPrimitive.CheckboxItem
  bind:ref
  bind:checked
  bind:indeterminate
  data-slot="menubar-checkbox-item"
  data-highlighted-color={getColor()}
  class={cn(
    'group neoretro-highlighted data-disabled:neoretro-disable relative flex cursor-default items-center gap-2 rounded py-1.5 ps-8 pe-2 text-sm outline-hidden select-none',
    className,
  )}
  {...restProps}
>
  {#snippet children({ checked, indeterminate })}
    <span
      class={cn(
        'neoretro-border group-data-highlighted:border-clr-highlighted group-data-[state=open]:border-clr-highlighted pointer-events-none absolute left-2 flex size-4 shrink-0 items-center justify-center rounded-sm transition-none',
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
</MenubarPrimitive.CheckboxItem>
