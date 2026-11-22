<script lang="ts">
  import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
  import { buttonVariants } from '#lib/components/ui/button/index.ts';
  import { cn } from '#lib/utils.ts';
  import { Calendar as CalendarPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), class: className, children, ...restProps }: CalendarPrimitive.NextButtonProps = $props();

  const getColors = getContext<() => { navColor: string }>('calendarColors');
</script>

{#snippet Fallback()}
  <ChevronRightIcon class="size-4" />
{/snippet}

<CalendarPrimitive.NextButton
  bind:ref
  data-pressable
  data-color={getColors().navColor}
  class={cn(
    buttonVariants({ size: 'icon', noShadow: false }),
    'neoretro-clr size-(--cell-size) p-0 select-none rtl:rotate-180',
    className,
  )}
  children={children || Fallback}
  {...restProps}
/>
