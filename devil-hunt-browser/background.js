/**
 * Devil Hunt Sensor — PASSIVE ONLY (Manifest V3)
 * Forwards sanitized network metadata to local bridge.
 * Does NOT modify, replay, inject, enumerate, or exploit.
 *
 * Limitation: chrome.webRequest onCompleted provides request metadata
 * (method, URL, status, type). Response bodies are NOT available and
 * are never requested or stored.
 */
const BRIDGE = 'http://127.0.0.1:3000/api/devil-hunt/bridge';
const DEFAULT_TARGET = 'supplier.meesho.com';
const SECRET_PARAM = /cookie|auth|token|password|otp|secret|session|authorization|api[_-]?key|bearer|csrf/i;

let sensor = {
  connected: false,
  connecting: false,
  paused: false,
  target: DEFAULT_TARGET,
  eventsSent: 0,
  lastEvent: null,
  lastError: null,
};

const recent = new Map();
const DEDUPE_MS = 2500;

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ sensor });
});

chrome.storage.local.get(['sensor'], (r) => {
  if (r.sensor) sensor = { ...sensor, ...r.sensor };
});

function save() {
  chrome.storage.local.set({ sensor });
}

function paramNamesFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return [...u.searchParams.keys()].filter((k) => !SECRET_PARAM.test(k)).slice(0, 40);
  } catch {
    return [];
  }
}

function hostOf(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function pathOf(urlStr) {
  try {
    return new URL(urlStr).pathname || '/';
  } catch {
    return '/';
  }
}

function dedupeKey(method, host, path, params, type) {
  return [method, host, path, (params || []).slice().sort().join(','), type || ''].join('|');
}

function shouldSend(key) {
  const now = Date.now();
  const last = recent.get(key) || 0;
  if (now - last < DEDUPE_MS) return false;
  recent.set(key, now);
  if (recent.size > 500) {
    const cut = now - DEDUPE_MS * 4;
    for (const [k, t] of recent) if (t < cut) recent.delete(k);
  }
  return true;
}

async function postBridge(payload) {
  const res = await fetch(BRIDGE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  let data = {};
  try {
    data = await res.json();
  } catch (_) {}
  return { httpOk: res.ok, data, status: res.status };
}

function mapCategory(path, type) {
  const p = (path || '').toLowerCase();
  if (/order/.test(p)) return 'ORDERS';
  if (/profile|user|account/.test(p)) return 'PROFILE';
  if (/catalog|product/.test(p)) return 'CATALOG';
  if (/payout|bank|payment/.test(p)) return 'PAYOUTS';
  if (/ticket|support/.test(p)) return 'TICKETS';
  if (/upload|file|media/.test(p)) return 'UPLOAD';
  if (/supply|supplier/.test(p)) return 'SUPPLY';
  if (type === 'xmlhttprequest' || type === 'fetch') return 'XHR';
  return 'OTHER';
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === 'GET_STATUS') {
      sendResponse({ sensor });
      return;
    }
    if (msg.type === 'CONNECT') {
      sensor.connecting = true;
      sensor.connected = false;
      sensor.paused = false;
      sensor.lastError = null;
      save();
      try {
        const ping = await postBridge({
          source: 'browser-extension',
          version: 1,
          type: 'SENSOR_HELLO',
          event: {
            method: 'PING',
            host: sensor.target,
            path: '/__devil_hunt_sensor_hello',
            status: null,
            category: 'SYSTEM',
            queryParamNames: [],
          },
        });
        const accepted = ping.data?.accepted === true || ping.data?.ok === true;
        if (accepted) {
          sensor.connected = true;
          sensor.connecting = false;
          sensor.lastError = null;
        } else {
          sensor.connected = false;
          sensor.connecting = false;
          sensor.lastError =
            ping.data?.reason || ping.data?.error || `HTTP ${ping.status}`;
        }
      } catch (e) {
        sensor.connected = false;
        sensor.connecting = false;
        sensor.lastError = String(e.message || e);
      }
      save();
      sendResponse({ sensor });
      return;
    }
    if (msg.type === 'DISCONNECT') {
      sensor.connected = false;
      sensor.connecting = false;
      sensor.paused = false;
      save();
      sendResponse({ sensor });
      return;
    }
    if (msg.type === 'PAUSE') {
      sensor.paused = true;
      save();
      sendResponse({ sensor });
      return;
    }
    if (msg.type === 'RESUME') {
      sensor.paused = false;
      save();
      sendResponse({ sensor });
    }
  })();
  return true;
});

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!sensor.connected || sensor.paused) return;

    const host = hostOf(details.url);
    const path = pathOf(details.url);
    const method = (details.method || 'GET').toUpperCase();
    const params = paramNamesFromUrl(details.url);
    const resourceType = details.type || 'other';

    if (host === '127.0.0.1' || host === 'localhost') {
      if (path.startsWith('/api/devil-hunt')) return;
    }

    if (host !== sensor.target) {
      const key = dedupeKey('OOS', host, '/', [], 'discovery');
      if (!shouldSend(key)) return;
      postBridge({
        source: 'browser-extension',
        version: 1,
        type: 'OUT_OF_SCOPE_DISCOVERY',
        event: {
          method: 'GET',
          host,
          path: '/',
          status: null,
          category: 'OUT_OF_SCOPE',
          queryParamNames: [],
        },
      }).catch(() => {});
      return;
    }

    const key = dedupeKey(method, host, path, params, resourceType);
    if (!shouldSend(key)) return;

    const event = {
      method,
      host,
      path,
      queryParamNames: params,
      bodyKeys: [],
      status: details.statusCode || null,
      category: mapCategory(path, resourceType),
      authState: 'UNKNOWN',
      contentType: '',
      responseStructure: resourceType,
      resourceType,
    };

    postBridge({
      source: 'browser-extension',
      version: 1,
      type: 'NETWORK',
      event,
    })
      .then((r) => {
        if (r.data?.ok || r.data?.accepted || r.httpOk) {
          sensor.eventsSent += 1;
          sensor.lastEvent = new Date().toISOString();
          sensor.lastError = null;
          save();
        } else if (r.data?.error || r.data?.reason) {
          sensor.lastError = r.data.error || r.data.reason;
          save();
        }
      })
      .catch((e) => {
        sensor.lastError = String(e.message || e);
        save();
      });
  },
  { urls: ['<all_urls>'] },
  []
);
