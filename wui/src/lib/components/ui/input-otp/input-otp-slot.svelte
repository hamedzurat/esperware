<script lang="ts">
  import { cn } from '#lib/utils.ts';
  import { PinInput as InputOTPPrimitive } from 'bits-ui';
  import { getContext } from 'svelte';

  let { ref = $bindable(null), cell, class: className, ...restProps }: InputOTPPrimitive.CellProps = $props();

  const getColor = getContext<() => string>('inputOtpColor');
  const color = $derived(getColor?.());
</script>

<InputOTPPrimitive.Cell
  {cell}
  bind:ref
  data-slot="input-otp-slot"
  data-color={color}
  class={cn(
    'border-border neoretro-invalid data-active:outline-ring relative flex size-12 items-center justify-center border-y-2 border-r-2 transition-all outline-none first:rounded-l first:border-l-2 last:rounded-r',
    color ? 'neoretro-clr' : 'bg-background text-foreground selection:bg-foreground selection:text-background',
    className,
  )}
  {...restProps}
>
  {cell.char}
  {#if cell.hasFakeCaret}
    <div class="pointer-events-none absolute inset-0 flex items-center justify-center">
      <div class="h-4 w-px bg-current"></div>
    </div>
  {/if}
</InputOTPPrimitive.Cell>
