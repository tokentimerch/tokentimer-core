import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    dedupe: ['react', 'react-dom', '@emotion/react', '@emotion/styled'],
  },
  esbuild: {
    drop: ['console', 'debugger'],
    legalComments: 'none',
    keepNames: false,
  },
  build: {
    chunkSizeWarningLimit: 500,
    sourcemap: true,
    // ES2022 eliminates most polyfills (class transforms, Math.trunc, etc.)
    target: 'es2022',
    modulePreload: {
      polyfill: false,
    },
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        // Enable code splitting for lazy-loaded pages
        manualChunks: {
          // Core vendor libs that rarely change (good cache hits)
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-chakra': [
            '@chakra-ui/react',
            '@emotion/react',
            '@emotion/styled',
            'framer-motion',
          ],
          // Tour only needed post-login
          'vendor-tour': ['react-joyride'],
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
  },
  optimizeDeps: {
    include: [
      '@emotion/react',
      '@emotion/styled',
      '@chakra-ui/react',
      '@chakra-ui/theme',
    ],
  },
  test: {
    environment: 'jsdom',
    setupFiles: './vitest.setup.js',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      // No coverage.include: Vitest 4 reports only files loaded by the unit suite.
      // A broad include forces App.jsx and other monoliths (0% hit) into the
      // denominator and fails the CI gate after the v8 remapping upgrade.
      exclude: ['src/**/*.test.{js,jsx}', 'src/main.jsx'],
    },
  },
});
