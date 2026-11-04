# NETY — web front-end

React 18 + TypeScript + Vite + Tailwind SPA for the NETY audit platform.
The production build is written to `../internal/server/dist`, which the Go
server embeds with `go:embed`, so the whole UI ships inside the single static
binary. Everything runs offline: system font stacks, inline SVG icons, no CDN,
no analytics, no external request at runtime.

## Nothing is installed on the host

Every command runs inside the `nety-toolchain:latest` image (Node 22 + Go).
From the **repository root**:

```sh
# install dependencies (writes package-lock.json)
docker run --rm -u $(id -u):$(id -g) -v $PWD:/src -w /src/web \
  -v $PWD/.cache/npm:/.npm -e npm_config_cache=/.npm -e HOME=/tmp \
  nety-toolchain:latest bash -c 'npm install --no-audit --no-fund'

# production build → ../internal/server/dist
docker run --rm -u $(id -u):$(id -g) -v $PWD:/src -w /src/web \
  -v $PWD/.cache/npm:/.npm -e npm_config_cache=/.npm -e HOME=/tmp \
  nety-toolchain:latest bash -c 'npm run build'

# type check
docker run --rm -u $(id -u):$(id -g) -v $PWD:/src -w /src/web \
  -v $PWD/.cache/npm:/.npm -e npm_config_cache=/.npm -e HOME=/tmp \
  nety-toolchain:latest bash -c 'npx tsc --noEmit'
```

`make web` (from the root) does the install + build in one go, and `make build`
chains it with the Go binaries.

## Dev loop

Run the Go server first — it owns the API, the session cookies and the event
WebSocket:

```sh
make build-go && ./dist/nety-linux-amd64        # listens on https://localhost:8443
```

Then start Vite with the same Docker invocation, publishing the port:

```sh
docker run --rm -it -u $(id -u):$(id -g) -v $PWD:/src -w /src/web \
  -v $PWD/.cache/npm:/.npm -e npm_config_cache=/.npm -e HOME=/tmp \
  -p 5173:5173 nety-toolchain:latest \
  bash -c 'npm run dev -- --host 0.0.0.0'
```

Open <http://localhost:5173>. `vite.config.ts` proxies `/api` (HTTP **and**
WebSocket upgrades) to `https://localhost:8443` with `secure: false`, so the
server's self-signed certificate is accepted in development. Session and CSRF
cookies survive the proxy because `changeOrigin` keeps the request same-site.

If the Go server runs elsewhere, change `server.proxy['/api'].target`.

## Layout

```
src/
  types/api.ts        hand-written mirror of internal/model/model.go — the contract
  lib/                api client (CSRF, 401 handling), query hooks, formatting, misc hooks
  live/               WebSocket client, event store, cache patching (see below)
  state/              auth and theme providers
  components/         UI kit (buttons, fields, tables, modals, badges), icons, shared panels
  pages/              login, missions, mission/* (overview … exports), admin/*
```

Routes: `/login`, `/missions`, `/missions/:id/{,networks,scans,scans/new,
scans/:scanId,hosts,services,findings,assets,matrix,exports}`, `/admin/users`,
`/admin/audit`.

## Live updates

`LiveProvider` (mounted by the mission layout) opens **one** WebSocket per open
mission on `/api/missions/{id}/events` and reconnects with exponential backoff
plus full jitter, capped at 30 s.

Each `model.Event` is applied to the TanStack Query cache in place
(`src/live/apply.ts`), so rows appear in open tables without a refetch:

| Event | Effect |
|---|---|
| `scan.status`, `scan.phase` | replace the scan in `['scan', id]` and in the mission's scan list |
| `scan.progress` | merge the partial `{phase, progress, stats, phases}` payload |
| `scan.log` | appended to the in-memory log buffer of that scan |
| `host`, `finding`, `reach` | upserted into every cached list whose network filter matches |
| `service` | patched in place in the paginated pages; a throttled refetch brings in brand-new rows without breaking the window |
| `asset`, `network` | upserted into their list caches |

High-frequency data (log lines and the rows streaming into the open scan) lives
in a mutable store read through `useSyncExternalStore`, with notifications
coalesced into one render per ~120 ms, so a scan emitting hundreds of events per
second stays smooth.

When the server reports `events dropped, resynchronise` (the client fell
behind), or after any reconnect, every affected query is invalidated and
refetched.

## Conventions

- **Dark by default**, light theme toggle, `prefers-color-scheme` respected when
  no explicit choice is stored. Colours are CSS variables on `:root`.
- **CSRF**: the `nety_csrf` cookie is read and sent back as `X-CSRF-Token` on
  every mutating request. Any `401` clears the session and bounces to `/login`.
- **Accessibility**: real `<button>`s, labelled inputs, visible focus rings,
  `Esc` closes drawers and modals, `/` focuses the page search, and severity is
  always spelled out, never colour alone.
- **Tables** scroll horizontally rather than breaking the layout; skeleton
  loaders stand in where a table is expected.
