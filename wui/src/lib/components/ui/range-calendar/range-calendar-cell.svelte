<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { RangeCalendar as RangeCalendarPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: RangeCalendarPrimitive.CellProps = $props();
</script>

<RangeCalendarPrimitive.Cell
  bind:ref
  class={cn('relative size-(--cell-size) p-0 text-center focus-within:z-20', className)}
  {...restProps}
/>
