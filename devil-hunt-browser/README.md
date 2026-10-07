# Devil Hunt Sensor (Chrome / Edge MV3)

Passive browser observation only. Does **not** attack, mutate, replay, or inject.

## Bridge

`POST http://127.0.0.1:3000/api/devil-hunt/bridge`

Envelope:

```json
{
  "source": "browser-extension",
  "version": 1,
  "type": "SENSOR_HELLO | NETWORK | OUT_OF_SCOPE_DISCOVERY",
  "event": { "method", "host", "path", "queryParamNames", "status", "category" }
}
```

## Limitation

`webRequest.onCompleted` provides metadata only (method, URL, status, type). Response bodies are not available and are never stored.

## Load (Edge)

1. Start: `node scripts/devil-hunt-live-server.mjs`
2. Console: START HUNT
3. `edge://extensions` → Developer mode → Load unpacked → this folder
4. Popup → CONNECT
5. Verify on `http://127.0.0.1:3000/demo` first
