import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

// `aitm web` serves dist/ and the /bus WebSocket bridge on one origin. In dev, Vite
// proxies /bus to a running `aitm web` (AITM_WEB, default 127.0.0.1:8081).
const bus = process.env.AITM_WEB ?? 'http://127.0.0.1:8081';

export default defineConfig({
  plugins: [solid()],
  resolve: { alias: { '~': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5173,
    strictPort: true,
    proxy: { '/bus': { target: bus, ws: true, changeOrigin: true } },
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    cssCodeSplit: true,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('@codemirror') || id.includes('@lezer')) return 'codemirror';
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
