<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Accordion as AccordionPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: AccordionPrimitive.ItemProps = $props();
</script>

<AccordionPrimitive.Item
  bind:ref
  data-slot="accordion-item"
  class={cn(
    'group neoretro-shadow neoretro-border relative rounded-none not-first:-mt-0.5 first:rounded-t-sm last:rounded-b-sm',
    className,
  )}
  {...restProps}
/>
