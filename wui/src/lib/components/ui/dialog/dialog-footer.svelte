<script lang="ts">
  import { Button } from '#lib/components/ui/button/index.ts';
  import { cn, type Color, type WithElementRef } from '#lib/utils.ts';
  import { Dialog as DialogPrimitive } from 'bits-ui';
  import type { HTMLAttributes } from 'svelte/elements';

  let {
    ref = $bindable(null),
    class: className,
    showCloseButton = true,
    closeColor = 'red',
    children,
    ...restProps
  }: WithElementRef<HTMLAttributes<HTMLDivElement>> & {
    showCloseButton?: boolean;
    closeColor?: Color;
  } = $props();
</script>

<div
  bind:this={ref}
  data-slot="dialog-footer"
  class={cn('flex flex-col gap-2 sm:flex-row sm:justify-end', className)}
  {...restProps}
>
  {#if showCloseButton}
    <DialogPrimitive.Close>
      {#snippet child({ props })}
        <Button {...props} color={closeColor} class="w-full sm:w-auto">Cancel</Button>
      {/snippet}
    </DialogPrimitive.Close>
  {/if}
  {@render children?.()}
</div>
