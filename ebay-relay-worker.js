// eBay relay for Lot Watch — Cloudflare Worker
//
// Why this exists: eBay's API does not send CORS headers, so a browser page
// cannot call it directly. This tiny worker sits in between. It also keeps your
// eBay Cert ID off your computer and out of the page.
//
// Setup (all in the browser, nothing to install):
//   1. dash.cloudflare.com -> Compute (Workers) -> Create -> Start from Hello World
//   2. Replace the editor contents with this file. Deploy.
//   3. Settings -> Variables and Secrets, add three secrets:
//        EBAY_APP_ID    your eBay App ID (Client ID), production keyset
//        EBAY_CERT_ID   your eBay Cert ID (Client Secret), production keyset
//        RELAY_KEY      any password you invent; the app sends it back
//      Optional, only if you use this URL for eBay's account deletion notices:
//        EBAY_VERIFY_TOKEN   32-80 chars, letters/numbers/_/- only
//   4. Copy the worker URL (https://something.workers.dev) into Lot Watch.
//
// Endpoints:
//   GET /search?<Browse API query>&key=RELAY_KEY   -> proxied item_summary/search
//   GET /  with ?challenge_code=...                -> eBay account deletion check
//   POST /                                          -> eBay account deletion notice

const EBAY = 'https://api.ebay.com';
let cachedToken = null;
let cachedUntil = 0;

function cors(extra) {
  const h = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,X-EBAY-C-MARKETPLACE-ID',
    'Access-Control-Max-Age': '86400'
  };
  if (extra) for (const k in extra) h[k] = extra[k];
  return h;
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: cors({ 'Content-Type': 'application/json' })
  });
}

async function getToken(env) {
  const now = Date.now();
  if (cachedToken && now < cachedUntil) return cachedToken;

  const basic = btoa(env.EBAY_APP_ID + ':' + env.EBAY_CERT_ID);
  const res = await fetch(EBAY + '/identity/v1/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Basic ' + basic
    },
    body: 'grant_type=client_credentials&scope=' +
          encodeURIComponent('https://api.ebay.com/oauth/api_scope')
  });

  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error('Token request failed: ' + JSON.stringify(data));
  }
  cachedToken = data.access_token;
  // Renew two minutes before eBay expires it.
  cachedUntil = now + (data.expires_in - 120) * 1000;
  return cachedToken;
}

async function sha256hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors() });
    }

    // eBay marketplace account deletion: verification handshake.
    const challenge = url.searchParams.get('challenge_code');
    if (challenge) {
      const endpoint = url.origin + url.pathname;
      const hash = await sha256hex(challenge + (env.EBAY_VERIFY_TOKEN || '') + endpoint);
      return json({ challengeResponse: hash });
    }

    // eBay marketplace account deletion: the actual notice. Nothing is stored
    // here, so acknowledging it is all that is required.
    if (request.method === 'POST') {
      return new Response(null, { status: 200, headers: cors() });
    }

    if (url.pathname !== '/search') {
      return json({ error: 'Use /search' }, 404);
    }

    if (env.RELAY_KEY && url.searchParams.get('key') !== env.RELAY_KEY) {
      return json({ error: 'Wrong or missing relay key' }, 401);
    }

    const params = new URLSearchParams(url.search);
    params.delete('key');
    const marketplace = params.get('marketplace') || 'EBAY_US';
    params.delete('marketplace');

    try {
      const token = await getToken(env);
      const upstream = await fetch(
        EBAY + '/buy/browse/v1/item_summary/search?' + params.toString(),
        {
          headers: {
            Authorization: 'Bearer ' + token,
            'X-EBAY-C-MARKETPLACE-ID': marketplace,
            'Content-Type': 'application/json'
          }
        }
      );
      const body = await upstream.text();
      // A 401 usually means the cached token went stale early. Drop it so the
      // next scan mints a fresh one.
      if (upstream.status === 401) { cachedToken = null; cachedUntil = 0; }
      return new Response(body, {
        status: upstream.status,
        headers: cors({ 'Content-Type': 'application/json' })
      });
    } catch (err) {
      return json({ error: String(err && err.message ? err.message : err) }, 502);
    }
  }
};
