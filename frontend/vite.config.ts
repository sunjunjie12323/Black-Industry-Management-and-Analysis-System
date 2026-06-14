import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (['react', 'react-dom', 'react-router-dom'].some((m) => id.includes(m))) {
            return 'vendor';
          }
          if (['antd', '@ant-design/icons'].some((m) => id.includes(m))) {
            return 'antd';
          }
          if (id.includes('@antv/g6')) {
            return 'g6';
          }
          if (id.includes('recharts')) {
            return 'recharts';
          }
          if (id.includes('gsap')) {
            return 'gsap';
          }
        },
      },
    },
  },
});
