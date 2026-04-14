import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { crx } from '@crxjs/vite-plugin'
import manifest from './manifest.json'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    crx({ manifest: manifest as any }),
  ],
  build: {
    rollupOptions: {
      input: {
        sidepanel: 'sidepanel.html',
      },
    },
  },
  server: {
    port: 5173,
    hmr: {
      port: 5173,
    },
  },
})
