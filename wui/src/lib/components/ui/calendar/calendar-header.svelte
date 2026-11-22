<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { Calendar as CalendarPrimitive } from 'bits-ui';

  let { ref = $bindable(null), class: className, ...restProps }: CalendarPrimitive.HeaderProps = $props();
</script>

<CalendarPrimitive.Header
  bind:ref
  class={cn('flex h-(--cell-size) w-full items-center justify-center gap-2 font-medium', className)}
  {...restProps}
/>
