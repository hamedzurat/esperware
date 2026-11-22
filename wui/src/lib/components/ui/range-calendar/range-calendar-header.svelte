<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { RangeCalendar as RangeCalendarPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: RangeCalendarPrimitive.HeaderProps = $props();
</script>

<RangeCalendarPrimitive.Header
  bind:ref
  class={cn('flex h-(--cell-size) w-full items-center justify-center gap-2 font-medium', className)}
  {...restProps}
/>
