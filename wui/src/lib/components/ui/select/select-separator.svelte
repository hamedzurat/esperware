<script lang="ts">
  import { Separator } from '#lib/components/ui/separator/index.ts';
  import { cn, type Color } from '#lib/utils.ts';
  import type { Separator as SeparatorPrimitive } from 'bits-ui';

  let {
    ref = $bindable(null),
    class: className,
    color = 'black',
    ...restProps
  }: SeparatorPrimitive.RootProps & {
    color?: 'black' | 'bright-black' | Color;
  } = $props();
</script>

<Separator
  bind:ref
  data-slot="select-separator"
  class={cn('neoretro-border -mx-1 my-1 h-px', className)}
  {color}
  {...restProps}
/>
