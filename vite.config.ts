import { defineConfig } from 'vitest/config';
export default defineConfig({
  server: {
    host: '127.0.0.1', port: 5173, strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:4173', changeOrigin: true,
        configure(proxy) {
          proxy.on('proxyReq', (outgoing, incoming) => {
            if (incoming.headers.origin === 'http://127.0.0.1:5173') outgoing.setHeader('origin', 'http://127.0.0.1:4173');
          });
        }
      }
    }
  },
  build: { target: 'es2022', sourcemap: false },
  test: { include: ['src/**/*.test.ts'], environment: 'node' }
});
