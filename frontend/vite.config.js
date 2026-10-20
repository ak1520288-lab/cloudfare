import react from '@vitejs/plugin-react'
import { env } from 'node:process'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      allow: ['..'],
    },
    proxy: {
      '/api': {
        target: env.ANTIFLAIR_API_URL || 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
})
