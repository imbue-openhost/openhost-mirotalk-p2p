'use strict';

/**
 * OpenHost auth shim for MiroTalk P2P.
 *
 * When the OpenHost zone owner is logged in, their browser's
 * requests arrive with a `zone_auth` cookie holding an RS256 JWT
 * signed by the OpenHost router. We verify the cookie's signature
 * against the router's JWKS (fetched from
 * `{OPENHOST_ROUTER_URL}/.well-known/jwks.json` at startup and
 * cached), and when `claims.sub === "owner"` treat the request
 * as coming from the zone owner. In that case we bypass
 * MiroTalk's own username/password host-protection flow:
 *
 *   * Add the requester's IP to MiroTalk's `authHost` allowlist
 *     (so subsequent checks via `isAuthorizedIP` return true).
 *   * Force `hostCfg.authenticated = true` on every request, since
 *     MiroTalk's stock `/` and `/newcall` handlers reset it to
 *     false and redirect to `/login` otherwise.
 *   * Register passthrough handlers for `/`, `/newcall`, `/logged`
 *     that skip MiroTalk's login redirect for owners.
 *
 * Note: we deliberately DO NOT trust the `X-OpenHost-Is-Owner`
 * header the router *also* sets on owner requests. The current
 * router (as of 2026-04-22) doesn't strip client-supplied copies
 * of that header on non-owner requests, so a hostile visitor can
 * spoof it. The `zone_auth` cookie, by contrast, is a signed JWT:
 * we verify the RSA signature with the router's public key, so
 * no cookie forgery is possible without access to the router's
 * private key.
 *
 * Guests (non-owner visitors) are unaffected. They can still join
 * rooms via direct URLs -- MiroTalk's `isAllowedRoomAccess` logic
 * lets any visitor into a room that already exists.
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const url = require('url');

const ZONE_COOKIE = 'zone_auth';
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000; // refetch JWKS every 10 minutes

function parseCookies(cookieHeader) {
    if (!cookieHeader) return {};
    return cookieHeader.split(';').reduce((acc, part) => {
        const eq = part.indexOf('=');
        if (eq < 0) return acc;
        const k = part.slice(0, eq).trim();
        const v = part.slice(eq + 1).trim();
        // cookie values arrive URL-encoded; JWTs are only [a-zA-Z0-9._-] so
        // decodeURIComponent is a no-op for them but we stay correct anyway.
        try { acc[k] = decodeURIComponent(v); } catch { acc[k] = v; }
        return acc;
    }, {});
}

function base64urlToBuffer(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

/**
 * Build an RSA public key object from a JWK {n, e}.
 */
function jwkToPublicKey(jwk) {
    // Node can import JWKs directly as of v15.
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * JWKS fetcher with refresh-on-miss + TTL caching.
 */
class JwksCache {
    constructor({ routerUrl, log }) {
        this.routerUrl = routerUrl;
        this.log = log;
        this._keys = [];
        this._fetchedAt = 0;
        this._refreshing = null;
    }

    _refresh() {
        if (this._refreshing) return this._refreshing;
        const target = new url.URL('/.well-known/jwks.json', this.routerUrl);
        this._refreshing = new Promise((resolve, reject) => {
            const client = target.protocol === 'https:' ? https : http;
            const req = client.get(target, (res) => {
                if (res.statusCode !== 200) {
                    res.resume();
                    return reject(new Error(`JWKS fetch failed: HTTP ${res.statusCode}`));
                }
                let body = '';
                res.setEncoding('utf8');
                res.on('data', (c) => (body += c));
                res.on('end', () => {
                    try {
                        const doc = JSON.parse(body);
                        const keys = (doc.keys || []).map(jwkToPublicKey);
                        this._keys = keys;
                        this._fetchedAt = Date.now();
                        this.log.info('[openhost-shim] refreshed JWKS', { keyCount: keys.length });
                        resolve(keys);
                    } catch (e) {
                        reject(e);
                    }
                });
            });
            req.on('error', reject);
            req.setTimeout(5000, () => {
                req.destroy(new Error('JWKS fetch timed out'));
            });
        }).finally(() => {
            this._refreshing = null;
        });
        return this._refreshing;
    }

    async getKeys() {
        if (this._keys.length && Date.now() - this._fetchedAt < JWKS_CACHE_TTL_MS) {
            return this._keys;
        }
        try {
            return await this._refresh();
        } catch (e) {
            // If we had stale keys, keep using them rather than erroring.
            if (this._keys.length) {
                this.log.warn('[openhost-shim] JWKS refresh failed, using stale cache', { err: e.message });
                return this._keys;
            }
            throw e;
        }
    }
}

/**
 * Verify a JWT compact string against a set of RSA public keys. Returns
 * the decoded payload object on success or null on any failure.
 *
 * Implements RS256 only (which is what OpenHost signs). We verify the
 * `exp` claim but ignore `iat`/`nbf` (the router doesn't set nbf).
 */
function verifyJwt(token, keys) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts;
    let header, payload;
    try {
        header = JSON.parse(base64urlToBuffer(headerB64).toString('utf8'));
        payload = JSON.parse(base64urlToBuffer(payloadB64).toString('utf8'));
    } catch {
        return null;
    }
    if (header.alg !== 'RS256') return null;
    const data = Buffer.from(headerB64 + '.' + payloadB64, 'utf8');
    const sig = base64urlToBuffer(sigB64);
    // Require an exp claim. Without one, a stolen token would be
    // valid forever. OpenHost always sets exp, but we defense-in-
    // depth check because we're the last line of defense.
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number') return null;
    if (payload.exp < now) return null;
    // iat must also be sane if present (reject clock-skew abuse).
    if (typeof payload.iat === 'number' && payload.iat > now + 300) return null;

    for (const key of keys) {
        try {
            const ok = crypto.verify('RSA-SHA256', data, key, sig);
            if (ok) return payload;
        } catch {
            // Try next key
        }
    }
    return null;
}

module.exports = function installOpenhostShim({ app, hostCfg, authHost, log, getIP, htmlInjector, views, OIDC }) {
    const routerUrl = process.env.OPENHOST_ROUTER_URL;
    if (!routerUrl) {
        log.warn('[openhost-shim] OPENHOST_ROUTER_URL not set; shim disabled');
        return;
    }

    const jwks = new JwksCache({ routerUrl, log });

    // Best-effort prefetch so the first owner request doesn't incur
    // the JWKS round-trip latency. Failure here is non-fatal -- the
    // shim will retry on the first request that needs verification.
    jwks.getKeys().catch((e) => {
        log.warn('[openhost-shim] initial JWKS fetch failed; will retry on demand', { err: e.message });
    });

    async function isOwner(req) {
        const cookies = parseCookies(req.headers.cookie || '');
        const token = cookies[ZONE_COOKIE];
        if (!token) return false;
        let keys;
        try {
            keys = await jwks.getKeys();
        } catch (e) {
            log.warn('[openhost-shim] JWKS unavailable; treating as guest', { err: e.message });
            return false;
        }
        const claims = verifyJwt(token, keys);
        if (!claims) return false;
        return claims.sub === 'owner';
    }

    // --- middleware: auto-authorize the owner's IP on every request ---
    app.use((req, res, next) => {
        if (!hostCfg.protected) return next();
        isOwner(req).then((ok) => {
            if (!ok) return next();
            const ip = getIP(req);
            if (!authHost.isAuthorizedIP(ip)) {
                authHost.setAuthorizedIP(ip, true);
                log.info('[openhost-shim] auto-authorized zone owner IP', { ip });
            }
            hostCfg.authenticated = true;
            next();
        }).catch((e) => {
            log.warn('[openhost-shim] owner check error; falling through as guest', { err: e.message });
            next();
        });
    });

    // --- route overrides: skip the login redirect for owners ---
    //
    // These handlers are registered BEFORE MiroTalk's own handlers
    // in server.js (because we're called from an early injection
    // point). Express's first-registered-wins route matching lets
    // us pre-empt the stock logic when the visitor is the owner.
    function ownerAwareRender(viewName) {
        return (req, res, next) => {
            if (OIDC.enabled || !hostCfg.protected) return next();
            isOwner(req).then((ok) => {
                if (!ok) return next();
                // hostCfg.authenticated is already true via the
                // middleware above; render the view directly
                // instead of redirecting to /login.
                return htmlInjector.injectHtml(views[viewName], res);
            }).catch((err) => {
                // Log so a silent parsing bug doesn't disappear; fall
                // through to MiroTalk's stock handler either way.
                log.warn('[openhost-shim] owner check errored; falling back to stock handler', {
                    view: viewName, err: err && err.message,
                });
                next();
            });
        };
    }

    app.get('/', ownerAwareRender('landing'));
    app.get('/newcall', ownerAwareRender('newCall'));

    // `/logged` is what MiroTalk redirects to after a successful
    // /login POST -- it checks the caller's IP is in the allowlist
    // and then redirects to `/`. For owners it's already in the
    // allowlist; short-circuit to `/`.
    app.get('/logged', (req, res, next) => {
        if (OIDC.enabled || !hostCfg.protected) return next();
        isOwner(req).then((ok) => {
            if (!ok) return next();
            return res.redirect('/');
        }).catch((err) => {
            log.warn('[openhost-shim] owner check errored on /logged', { err: err && err.message });
            next();
        });
    });

    log.info('[openhost-shim] installed; owner auto-auth active via zone_auth cookie verification');
};
