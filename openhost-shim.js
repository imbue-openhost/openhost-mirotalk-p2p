'use strict';

/**
 * OpenHost auth shim for MiroTalk P2P.
 *
 * When the OpenHost zone owner is logged in, their browser
 * requests arrive with `X-OpenHost-Is-Owner: true` injected by the
 * OpenHost router (see openhost/compute_space/compute_space/web/
 * routes/proxy.py). We use that signal to bypass MiroTalk's own
 * username/password host-protection flow:
 *
 *   * Add the requester's IP to MiroTalk's `authHost` allowlist
 *     (so subsequent checks via `isAuthorizedIP` return true).
 *   * Force `hostCfg.authenticated = true` on every request, since
 *     MiroTalk's stock `/` and `/newcall` handlers reset it to
 *     false and redirect to `/login` otherwise.
 *   * Register passthrough handlers for `/`, `/newcall`, `/logged`
 *     that skip MiroTalk's login redirect for owners.
 *
 * Guests (non-owner visitors) are unaffected. They can still join
 * rooms via direct URLs -- the `isAllowedRoomAccess` logic lets
 * any visitor into a room that already exists.
 *
 * The shim is deliberately non-invasive: if the
 * `X-OpenHost-Is-Owner` header is not present (e.g. in a non-
 * OpenHost deployment), the shim is a no-op and MiroTalk's normal
 * flow runs.
 */

module.exports = function installOpenhostShim({ app, hostCfg, authHost, log, getIP, htmlInjector, views, OIDC }) {
    const HEADER = 'x-openhost-is-owner';

    function isOpenhostOwner(req) {
        return req.headers && req.headers[HEADER] === 'true';
    }

    // --- middleware: auto-authorize the owner's IP on every request ---
    //
    // MiroTalk's `authHost` is an in-memory Map<ip, true>. We add the
    // owner's IP to it the first time we see them, and then force
    // `hostCfg.authenticated = true` on every owner request because
    // the stock `/` and `/newcall` handlers unconditionally reset
    // that flag to false before rendering.
    app.use((req, res, next) => {
        if (!isOpenhostOwner(req) || !hostCfg.protected) {
            return next();
        }
        const ip = getIP(req);
        if (!authHost.isAuthorizedIP(ip)) {
            authHost.setAuthorizedIP(ip, true);
            log.info('[openhost-shim] auto-authorized zone owner IP', { ip });
        }
        hostCfg.authenticated = true;
        next();
    });

    // --- route overrides: skip the login redirect for owners ---
    //
    // These handlers are registered BEFORE MiroTalk's own handlers
    // in server.js (because we're called from an early injection
    // point). Express's first-registered-wins route matching lets
    // us pre-empt the stock logic when the visitor is the owner.
    app.get('/', (req, res, next) => {
        if (!isOpenhostOwner(req) || OIDC.enabled || !hostCfg.protected) {
            return next();
        }
        // hostCfg.authenticated is already true via the middleware
        // above; render the landing page directly instead of
        // redirecting to /login.
        return htmlInjector.injectHtml(views.landing, res);
    });

    app.get('/newcall', (req, res, next) => {
        if (!isOpenhostOwner(req) || OIDC.enabled || !hostCfg.protected) {
            return next();
        }
        return htmlInjector.injectHtml(views.newCall, res);
    });

    // `/logged` is what MiroTalk redirects to after a successful
    // /login POST -- it sanity-checks that the caller's IP is in
    // the allowlist and then redirects to `/`. For owners it's
    // already in the allowlist; short-circuit the check.
    app.get('/logged', (req, res, next) => {
        if (!isOpenhostOwner(req) || OIDC.enabled || !hostCfg.protected) {
            return next();
        }
        return res.redirect('/');
    });

    log.info('[openhost-shim] installed; owner auto-auth active when X-OpenHost-Is-Owner=true');
};
