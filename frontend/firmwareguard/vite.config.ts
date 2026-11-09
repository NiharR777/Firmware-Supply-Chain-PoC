
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig(() => ({
  plugins: [react(), tailwindcss()],

  resolve: {
    alias: {
      '@': resolve(__dirname, '.'),
    },
  },

  server: {
  host: "0.0.0.0",
  port: 3001,
  strictPort: true,
  proxy: {
    "/api": {
      target: "http://127.0.0.1:8010",
      changeOrigin: true,
    },
  },
},
}));
