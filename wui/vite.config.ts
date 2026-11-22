import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    tailwindcss(),
    sveltekit({
      compilerOptions: {
        // Force runes mode for the project, except for libraries. Can be removed in svelte 6.
        runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true),
      },
      adapter: adapter({ fallback: '404.html' }),
      preprocess: vitePreprocess(),
    }),
  ],
  build: {
    sourcemap: false,
    cssMinify: 'lightningcss',
    target: 'esnext',
    assetsInlineLimit: 4096,
  },
  optimizeDeps: {
    include: [
      '@lucide/svelte',
      '@videojs/html',
      'bits-ui',
      'clsx',
      'mode-watcher',
      'tailwind-merge',
      'tailwind-variants',
    ],
  },
});
