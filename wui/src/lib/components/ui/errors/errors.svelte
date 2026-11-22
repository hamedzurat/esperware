<script lang="ts">
  import ArrowLeft from '@lucide/svelte/icons/arrow-left';

  let { message = 'System Failure' }: { message?: string } = $props();
</script>

<div class="relative flex min-h-screen w-full flex-col items-center justify-center overflow-hidden bg-black">
  <!-- Scanline Overlay -->
  <div
    class="pointer-events-none absolute inset-0 z-10 bg-[linear-gradient(rgba(0,0,0,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.04),rgba(0,255,0,0.02),rgba(0,0,255,0.04))] bg-size-[100%_8px,6px_100%] opacity-40"
  ></div>

  <!-- SMPTE Content Background -->
  <div class="absolute inset-0 z-0 flex size-full flex-col">
    <div class="flex h-[84%] w-full">
      <div class="flex-1 bg-white"></div>
      <div class="bg-yellow flex-1"></div>
      <div class="bg-cyan flex-1"></div>
      <div class="bg-green flex-1"></div>
      <div class="bg-magenta flex-1"></div>
      <div class="bg-red flex-1"></div>
      <div class="bg-blue flex-1"></div>
    </div>

    <div class="flex h-[8%] w-full">
      <div class="bg-blue flex-1"></div>
      <div class="flex-1 bg-black"></div>
      <div class="bg-magenta flex-1"></div>
      <div class="flex-1 bg-black"></div>
      <div class="bg-cyan flex-1"></div>
      <div class="flex-1 bg-black"></div>
      <div class="flex-1 bg-white"></div>
    </div>

    <div class="flex h-[8%] w-full">
      <div class="w-1/6 bg-white/50"></div>
      <div class="w-1/6 bg-white/10"></div>
      <div class="w-1/6 bg-white/40"></div>
      <div class="w-1/6 bg-white/30"></div>
      <div class="w-1/6 bg-white/60"></div>
      <div class="w-1/6 bg-white/20"></div>
    </div>
  </div>

  <div class="relative z-20 flex w-full flex-col items-center justify-center px-4">
    <button
      onclick={() => history.back()}
      class="group neoretro-border flex max-w-[95vw] cursor-pointer appearance-none flex-col items-center justify-center border-none bg-black p-4 font-[inherit] md:p-6"
    >
      <h1
        class="mb-0 truncate text-center font-mono text-3xl leading-none font-black tracking-wide text-white uppercase sm:text-4xl md:text-5xl lg:text-6xl"
      >
        <span class="inline-block group-hover:hidden">{message}</span>
        <ArrowLeft class="hidden size-16 align-middle group-hover:inline-block" />
      </h1>
    </button>
  </div>
</div>
