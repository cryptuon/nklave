import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API requests to Nklave during development
      '/api': {
        target: 'http://localhost:9000',
        changeOrigin: true,
      },
      '/upcheck': 'http://localhost:9000',
      '/health': 'http://localhost:9000',
      '/status': 'http://localhost:9000',
      '/reload': 'http://localhost:9000',
      '/admin': 'http://localhost:9000',
      '/livez': 'http://localhost:9000',
      '/readyz': 'http://localhost:9000',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
