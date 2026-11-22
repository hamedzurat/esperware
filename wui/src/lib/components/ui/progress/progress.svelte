<script lang="ts">
  import { cn, type Color, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { Progress as ProgressPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    class: className,
    max = 100,
    noShadow,
    value,
    indicatorColor,
    trackColor,
    ...restProps
  }: WithoutChildrenOrChild<ProgressPrimitive.RootProps> & {
    noShadow?: boolean;
    indicatorColor: Color;
    trackColor?: Color;
  } = $props();
</script>

<ProgressPrimitive.Root
  bind:ref
  data-slot="progress"
  data-color={trackColor}
  class={cn(
    'neoretro-border neoretro-clr relative h-4 w-full overflow-hidden rounded',
    noShadow ? '' : 'neoretro-shadow',
    className,
  )}
  {value}
  {max}
  {...restProps}
>
  <div
    data-slot="progress-indicator"
    data-color={indicatorColor}
    class={cn('neoretro-clr absolute inset-0 rounded transition-all')}
    style="transform: translateX(-{100 - (100 * (value ?? 0)) / (max ?? 1)}%)"
  ></div>
</ProgressPrimitive.Root>
