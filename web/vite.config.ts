import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// The Go server embeds ../internal/server/dist with go:embed and always serves
// the SPA from the root, so assets are referenced absolutely.
//
// A relative base ('./') must NOT be used here: the client-side router has
// nested routes such as /missions/1/scans/1, and on a reload or a shared deep
// link the browser would resolve ./assets/… against /missions/1/scans/,
// getting index.html back instead of the bundle - a blank page.
export default defineConfig({
  base: '/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: '../internal/server/dist',
    emptyOutDir: false,
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
})
