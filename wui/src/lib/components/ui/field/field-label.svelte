<script lang="ts">
  import { Label } from '#lib/components/ui/label/index.ts';
  import { cn } from '#lib/utils.ts';
  import type { ComponentProps } from 'svelte';

  let { ref = $bindable(null), class: className, children, ...restProps }: ComponentProps<typeof Label> = $props();
</script>

<Label
  bind:ref
  data-slot="field-label"
  class={cn(
    'group-data-[disabled=true]/field:neoretro-disable has-[>[data-slot=field]]:neoretro-border flex w-fit gap-2 leading-snug has-[>[data-slot=field]]:w-full has-[>[data-slot=field]]:flex-col has-[>[data-slot=field]]:rounded *:data-[slot=field]:p-4',
    className,
  )}
  {...restProps}
>
  {@render children?.()}
</Label>
