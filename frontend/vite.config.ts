import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In dev the API is proxied, so the browser only ever talks to one origin (no CORS needed).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8080' },
  },
})
