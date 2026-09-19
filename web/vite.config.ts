import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'
import { apiNetworkOnlyUrlPattern, navigateFallbackDenylist } from './pwa.js'

export default defineConfig({
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: 'autoUpdate',
      injectRegister: false,
      includeAssets: ['favicon.svg', 'apple-touch-icon.png', 'push-sw.js'],
      manifest: {
        name: 'OpenBao Authorizer',
        short_name: 'Authorizer',
        description: 'Review and approve OpenBao control group requests.',
        theme_color: '#151515',
        background_color: '#151515',
        display: 'standalone',
        orientation: 'any',
        scope: '/',
        start_url: '/',
        categories: ['security', 'business', 'productivity'],
        icons: [
          { src: 'pwa-192x192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
          { src: 'pwa-512x512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
          { src: 'pwa-512x512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,png,ico}'],
        navigateFallback: '/index.html',
        navigateFallbackDenylist,
        importScripts: ['push-sw.js'],
        runtimeCaching: [
          {
            urlPattern: apiNetworkOnlyUrlPattern,
            handler: 'NetworkOnly',
            options: { cacheName: 'openbao-api-network-only' },
          },
        ],
      },
    }),
  ],
})
