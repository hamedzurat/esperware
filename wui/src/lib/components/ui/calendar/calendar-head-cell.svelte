<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Calendar as CalendarPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: CalendarPrimitive.HeadCellProps = $props();
</script>

<CalendarPrimitive.HeadCell
  bind:ref
  class={cn('flex size-(--cell-size) w-full items-center justify-center p-0', className)}
  {...restProps}
/>
