<script lang="ts">
  import { Input } from '#lib/components/ui/input/index.ts';
  import { cn } from '#lib/utils.ts';
  import type { ComponentProps } from 'svelte';

  let {
    ref = $bindable(null),
    value = $bindable(),
    class: className,
    ...props
  }: ComponentProps<typeof Input> = $props();
</script>

<Input
  bind:ref
  data-slot="input-group-control"
  noShadow={true}
  class={cn('flex-1 rounded border-0 bg-transparent shadow-none', className)}
  bind:value
  {...props}
/>
