<script lang="ts">
  import './layout.css';

  import favicon from '#lib/assets/favicon.svg';
  import ThemeInit from '#lib/components/ui/style/theme-init.svelte';

  import type { LayoutProps } from './$types';

  let { children }: LayoutProps = $props();
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
</svelte:head>

<ThemeInit>
  {@render children?.()}
</ThemeInit>
