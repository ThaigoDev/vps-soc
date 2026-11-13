import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Builds the presentation alone, as a single chunk, so scripts/inline-presentation.mjs can
// fold it into one self-contained HTML file.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist-presentation',
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    chunkSizeWarningLimit: 4000,
    rollupOptions: {
      input: 'presentation.html',
      output: { inlineDynamicImports: true },
    },
  },
})
