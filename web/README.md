# Frontend

React 19, TypeScript, Tailwind CSS 4, Vite, and `vite-plugin-pwa` frontend for the OpenBao Authorizer service.

```sh
npm install
npm run dev      # proxies /api to 127.0.0.1:8080
npm test -- --run
npm run lint
npm run build
```

The app never writes OpenBao tokens to browser storage. The production service worker precaches static assets only and treats all `/api/v1/` requests as network-only. Web Push notifications intentionally contain no request details.

See the repository-level [`README.md`](../README.md) for server setup and the security model.
