---
name: verify
description: Build, launch, and drive AiFw (API + web UI) locally on Linux/WSL to verify changes end-to-end.
---

# Verifying AiFw changes locally (Linux/WSL, mock pf backend)

## Build & launch the API serving the real UI

```bash
cd aifw-ui && npm run build          # static export to aifw-ui/out/
cargo build -p aifw-api              # debug build is fine (~1 min warm)

# Scratch DB + plain HTTP; PfMock backend is selected automatically on Linux.
AIFW_JWT_SECRET=devsecret ./target/debug/aifw-api \
  --db /tmp/aifw-verify/aifw.db \
  --jwt-key-file /tmp/aifw-verify/jwt.key \
  --listen 127.0.0.1:18080 \
  --no-tls \
  --ui-dir aifw-ui/out &
```

Gotchas:
- Without `--no-tls` the API auto-generates a self-signed cert into
  `/usr/local/etc/aifw/tls/` and dies with `Permission denied`.
- `--no-tls` refuses non-loopback listeners unless
  `--allow-plaintext-external` is also passed.

## Create a login

`POST /api/v1/auth/register` is public; the first user becomes admin:

```bash
curl -s -X POST http://127.0.0.1:18080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"verify","password":"Verify!pass1","email":"v@example.com"}'
```

Then log in through the UI at `http://127.0.0.1:18080/login/` (trailing
slash matters — static export uses `trailingSlash: true`).

## Driving the UI in a browser

- The `chrome-devtools` CLI daemon's own Chrome launch can fail on WSL
  ("Target closed"). Workaround: launch Chrome yourself with
  `--remote-debugging-port=9222` and run
  `chrome-devtools start --browserUrl=http://127.0.0.1:9222`.
- Chrome binary lives under `~/.cache/puppeteer/chrome/*/chrome-linux64/chrome`.
- **WSLg never reports tab/window occlusion**, so
  `document.visibilityState` stays `"visible"` no matter what — tab
  switching, `Target.activateTarget`, and window minimize all fail to
  hide a page. To test visibility-dependent behavior, synthesize the
  signal at the DOM boundary from a CDP `Runtime.evaluate`:
  `Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>'hidden'});
  document.dispatchEvent(new Event('visibilitychange'));`
- Poll timings are easiest read from
  `performance.getEntriesByType('resource')` filtered by API path.
