import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/postcss'
import path from 'node:path'

// Hanzo KMS admin SPA.
//
// Single-page React app served from KMS_FRONTEND_DIR by kmsd's mux.
// All API calls go to /v1/kms/* — same origin as the SPA in production.
// In dev, Vite proxies /v1/kms to the local kmsd listener on :8443.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  css: {
    postcss: {
      plugins: [tailwindcss()],
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    port: 5173,
    proxy: {
      '/v1/kms': {
        target: 'http://127.0.0.1:8443',
        changeOrigin: true,
        secure: false,
      },
      '/healthz': {
        target: 'http://127.0.0.1:8443',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
