<script lang="ts">
  import { cn, type Color, type WithoutChildrenOrChild } from '#lib/utils.ts';
  import { Slider as SliderPrimitive } from 'bits-ui';
  import type { Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    value = $bindable([0]),
    type = 'multiple',
    orientation = 'horizontal',
    noShadow = false,
    color,
    buffered = undefined,
    max = 100,
    min = 0,
    step = 1,
    class: className,
    onValueChange,
    onValueCommit,
    children,
    ...restProps
  }: Omit<
    WithoutChildrenOrChild<SliderPrimitive.RootProps>,
    'value' | 'type' | 'onValueChange' | 'onValueCommit' | 'max' | 'min' | 'step'
  > & {
    value?: number[];
    type?: 'multiple';
    onValueChange?: (value: number[]) => void;
    onValueCommit?: (value: number[]) => void;
    noShadow?: boolean;
    color: Color;
    buffered?: number;
    max?: number;
    min?: number;
    step?: number;
    children?: Snippet<[number]>;
  } = $props();

  let isHovering = $state(false);
  let hoverPercent = $state(0);
  let hoverValue = $derived(
    Math.max(min, Math.min(max, min + Math.round(((hoverPercent / 100) * (max - min)) / step) * step)),
  );

  function handlePointerMove(e: PointerEvent) {
    const target = e.currentTarget as HTMLElement;
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const pct =
      orientation === 'horizontal'
        ? ((e.clientX - rect.left) / rect.width) * 100
        : ((rect.bottom - e.clientY) / rect.height) * 100;
    const clampedPct = Math.max(0, Math.min(100, pct));
    hoverPercent = clampedPct;
    isHovering = true;
  }

  function handlePointerLeave() {
    isHovering = false;
  }
</script>

<SliderPrimitive.Root
  bind:ref
  bind:value={value as never}
  data-slot="slider"
  {orientation}
  {type}
  {max}
  {min}
  {step}
  {onValueChange}
  {onValueCommit}
  onpointermove={handlePointerMove}
  onpointerleave={handlePointerLeave}
  class={cn(
    'peer data-disabled:neoretro-disable relative flex w-full cursor-pointer touch-none items-center rounded select-none data-[orientation=vertical]:h-full data-[orientation=vertical]:min-h-44 data-[orientation=vertical]:w-auto data-[orientation=vertical]:flex-col',
    className,
  )}
  children={sliderContent}
  {...restProps}
/>

{#snippet sliderContent({ thumbItems: thumbs }: { thumbItems: { index: number }[] })}
  <span
    data-orientation={orientation}
    data-slot="slider-track"
    class={cn(
      'neoretro-border bg-background relative z-10 w-full grow overflow-hidden rounded data-[orientation=horizontal]:h-3 data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-3',
      noShadow ? '' : 'neoretro-shadow',
    )}
  >
    {#if buffered !== undefined}
      <div
        data-slot="slider-buffered"
        data-color={color}
        data-orientation={orientation}
        class="neoretro-clr absolute bottom-0 left-0 opacity-30 data-[orientation=horizontal]:top-0 data-[orientation=horizontal]:h-full data-[orientation=vertical]:w-full"
        style={orientation === 'horizontal'
          ? `width: ${Math.max(0, Math.min(100, buffered))}%`
          : `height: ${Math.max(0, Math.min(100, buffered))}%`}
      ></div>
    {/if}
    <SliderPrimitive.Range
      data-slot="slider-range"
      data-color={color}
      class="neoretro-clr absolute data-[orientation=horizontal]:h-full data-[orientation=vertical]:w-full"
    />
  </span>

  {#each thumbs as thumb (thumb.index)}
    <!-- Child snippet lets us map the properties natively while cloning position for the z-0 shadow -->
    <SliderPrimitive.Thumb index={thumb.index}>
      {#snippet child({ props })}
        {#if !noShadow}
          <!-- Ghost shadow under the Z-10 track -->
          <div
            class="neoretro-shadow pointer-events-none absolute z-0 block size-5 rounded outline-hidden"
            style={props.style as string}
          ></div>
        {/if}

        <!-- Actual interactive thumb on top of the Z-10 track -->
        <span
          {...props}
          data-slot="slider-thumb"
          data-color={color}
          class="neoretro-focus neoretro-border neoretro-clr absolute z-20 block size-5 rounded border-2"
        ></span>
      {/snippet}
    </SliderPrimitive.Thumb>
  {/each}

  {#if isHovering && children}
    <div
      class={cn(
        'pointer-events-none absolute z-30 flex flex-col items-center gap-1.5',
        orientation === 'horizontal' ? 'bottom-full mb-2 -translate-x-1/2' : 'left-full ml-2 -translate-y-1/2',
      )}
      style={orientation === 'horizontal' ? `left: ${hoverPercent}%` : `top: ${100 - hoverPercent}%`}
    >
      <div class="bg-background text-foreground neoretro-border neoretro-shadow rounded px-2 py-1 font-mono text-xs">
        {@render children(hoverValue)}
      </div>
    </div>
  {/if}
{/snippet}
