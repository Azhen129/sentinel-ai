import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_')
  const target = new URL(env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000')
  if (!['http:', 'https:'].includes(target.protocol) || !['127.0.0.1', '[::1]'].includes(target.hostname) || target.username || target.password || target.pathname !== '/' || target.search || target.hash || target.port === '0') {
    throw new Error('VITE_API_PROXY_TARGET must be a literal loopback HTTP(S) origin without credentials, paths, queries, or fragments')
  }
  return {
    plugins: [react()],
    server: { port: 5173, strictPort: true, proxy: { '/api': { target: target.origin, changeOrigin: true } } },
    preview: { port: 4173 },
  }
})
