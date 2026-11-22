<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Tabs as TabsPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: TabsPrimitive.ListProps = $props();
</script>

<TabsPrimitive.List
  bind:ref
  data-slot="tabs-list"
  class={cn(
    'flex h-12 w-full items-stretch rounded pr-1 pb-1 *:relative *:focus-visible:z-20 [&>*:not(:first-child)]:-ml-0.5 [&>*:not(:first-child)]:rounded-s-none [&>*:not(:last-child)]:rounded-e-none',
    className,
  )}
  {...restProps}
/>
