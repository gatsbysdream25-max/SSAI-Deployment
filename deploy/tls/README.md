# HTTPS in front of the hub

The hub speaks plain HTTP on its own. Anything that can watch the network segment can read the admin session cookie,
node tokens, the API key and every threat in transit. A pilot must put a TLS-terminating reverse proxy in front and
stop the hub from answering plain HTTP to anyone else.

## Steps

1. **Pick a certificate source.**
   - Private install (typical for a bank): a certificate from your organisation's CA, or an internal CA you install on
     the admin PCs, for a name that resolves inside your network (for example `ssai.bank.example`).
   - Public name reachable on ports 80 and 443: Caddy can fetch a Let's Encrypt certificate by itself.
2. **Install the proxy** (Caddy or nginx) on the same machine, using `Caddyfile.example` or `nginx.conf.example`
   in this directory. Replace the host name and certificate paths.
3. **Make the hub listen on this machine only.** Re-run the installer with `--bind 127.0.0.1` (or set `SSAI_BIND=127.0.0.1`
   in `.env` and change the gunicorn `-b` address), then restart `swarmsentinel`. Block port 5000 from other hosts in
   the firewall too.
4. **Tell the hub about the proxy** in the hub's `.env`:
   ```
   SSAI_TRUSTED_PROXIES=127.0.0.1
   SSAI_COOKIE_SECURE=1
   ```
   The first makes the hub believe `X-Forwarded-For` and `X-Forwarded-Proto` from the proxy and from nobody else; the
   second marks the session cookie `Secure` so a browser never sends it over plain HTTP.
5. **Check it works**, then turn on HSTS:
   ```
   deploy/check-tls.sh https://ssai.bank.example
   ```
   When every line says PASS, add `SSAI_HSTS=1` to `.env` and restart. HSTS makes browsers refuse plain HTTP for the host
   for a year, so turn it on only after HTTPS is confirmed (and keep `includeSubDomains` off unless every subdomain is HTTPS).
6. **Point nodes at the HTTPS address** (`--hub-url https://ssai.bank.example`). If the certificate comes from an internal
   CA, the node machines must trust that CA.

## The wall display (kiosk)

The kiosk's own proxy must send the viewer key to the hub: `proxy_set_header X-SSAI-Viewer <SSAI_VIEWER_KEY from .env>;`
on its `/dashboard` and `/api/` locations, and it must reach the hub over HTTPS too.

## Notes

- The proxy does not fix CORS, and CORS is not authentication. The hub's own login and keys still decide who may do what.
- Keep the proxy's access log: it is the record of who connected (the hub sees only the proxy's address unless
  `SSAI_TRUSTED_PROXIES` is set).
