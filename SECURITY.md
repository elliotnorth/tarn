# Security

## Reporting a problem

Use GitHub's private vulnerability reporting on this repository (the **Security**
tab, then **Report a vulnerability**). Please don't open a public issue for a
security bug.

Include the tarn version (`tarn status`), what you did, and what happened. You'll
get a reply within a week. Fixes go into a new release, and the release notes say
what was fixed once most people can upgrade.

Only the latest release gets fixes.

## Threat model

tarn sits on one machine in your tailnet. It answers DNS for one zone, holds a
wildcard certificate for that zone, and proxies HTTPS to your services. This
section says what it protects, from whom, and what it doesn't try to do.

### What's worth stealing

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| The wildcard private key | State directory, mode 0600 | Anyone holding it can impersonate every `*.<zone>` name to a device that resolves them |
| The Cloudflare API token | A root-only file passed in through systemd `LoadCredential`, or, after the setup wizard, the state directory, mode 0600 | It can edit DNS for the zone, so it can get new certificates |
| The ACME account key | State directory, mode 0600 | Lets someone act as your Let's Encrypt account, including revoking certificates |
| The page password and sessions | A bcrypt hash in the config file; sessions in memory | The page can change services, and so where traffic goes |
| Signed links passing through the proxy | In memory only | They work as passwords until they expire |
| The setup code | State directory, mode 0600, and the log, until setup finishes | Whoever has it can finish setup: choose the zone, token and page password |
| Which device asks for which name | Not stored | A full query log would show who uses what |

### Who we defend against

**A device on the tailnet that you don't fully trust**: a guest, a shared node, or
your own device after it's been compromised. This is the main attacker. Every
device that can reach tarn's tailnet IP can send it DNS queries and HTTPS requests.

- DNS answers only for its own zone and never recurses, so tarn can't be used as
  an open resolver or to probe other names. Queries outside the zone are refused
  with nothing in the reply.
- The DNS responder is fuzzed in CI. Malformed queries get a reply or are dropped.
  They never crash tarn, and the log lines they cause are rate limited.
- Only blocked and failed queries are logged, rate limited. Successful lookups are
  never logged.
- The management port listens on loopback only. When tarn proxies services, it is
  published as `tarn.<zone>` unless `-status-name ""` is set; through the proxy,
  everything except the page and sign-in needs a session or the records token.
- Every change needs a session, the `X-Tarn-Request` header, a matching `Origin`
  and a loopback `Host`. Those checks run before the password is looked at.
  Repeated wrong passwords lock sign-in for a while, and each attempt is logged
  with the source IP.
- The setup wizard runs only on a fresh install with no config file. It serves plain
  HTTP on the tailnet address, which WireGuard encrypts, and closes when setup
  finishes. Every request needs the one-time code (about 60 bits), the
  `X-Tarn-Request` header, a matching `Origin` and an IP address as the `Host`.
  Five wrong codes lock it for 15 minutes. It saves the token only after Cloudflare
  accepts it, and starts on Let's Encrypt staging.
- Some settings can never be changed from the page because they would amount to
  running commands or reading files on the host: the tailscale binary and socket,
  the state directory, file paths, the management address and the Cloudflare
  token.
- Plain `http://` upstreams must be on the tailnet, a private LAN or loopback, and
  hostnames are checked again after every DNS lookup. Link-local addresses, which
  include cloud metadata endpoints, are always refused.

**Someone on the internet.** tarn opens no ports to the internet. Its only outbound
connections go to Let's Encrypt and your DNS provider's API, during issuance and
renewal. There's no update checker, telemetry or crash reporting.

**Someone on your LAN who isn't on the tailnet.** DNS and HTTPS bind to the tailnet
IP only by default. A `host=preserve` upstream on a private LAN address isn't
encrypted between tarn and the app. docs/ADVANCED.md says so.

**A tampered release.** Release checksums are signed with an Ed25519 key that lives
only in a GitHub Actions secret. The installer checks the signature against
`deploy/release.pub` before installing anything. Builds are reproducible, so
anyone can rebuild a tag and compare.

**A backup file.** `tarn backup` archives hold the private keys, so they're written
owner-only and never overwrite an existing file. `tarn restore` treats an archive
as untrusted. It refuses links, absolute paths, `..` and oversized files, extracts
beside the state directory before swapping it in, and writes outside the state
directory only to a services path given on the command line. The archive never
chooses that path.

### What tarn doesn't protect against

- **Root on tarn's host.** Root can read the key and the token. tarn limits what
  its own process can do through systemd: `DynamicUser`, `ProtectSystem=strict`,
  `NoNewPrivileges`, and only `CAP_NET_BIND_SERVICE`. It can't defend the host
  from its own administrator.
- **Who can reach which service.** That's your Tailscale ACL. tarn doesn't change
  tailnet settings, and it can't stop a device that can reach an app's port
  directly from going around the proxy.
- **The apps behind the proxy.** tarn decrypts every request, including
  passthrough, and forwards it. It doesn't filter or check what the app does with
  the request.
- **Browsers using DNS over HTTPS.** They never ask tailnet DNS, so they don't
  see tarn's names at all.
- **A leaked Cloudflare token.** Scope it to one zone with Zone:Read and DNS:Edit
  only, as the README describes. That limits the damage to that zone.
- **Certificate Transparency.** Public logs show the wildcard `*.<zone>`. They
  never show individual service or device names.

### If something leaks

- **Wildcard key:** stop tarn, delete `cert.pem` and `key.pem` under
  `production/zones/<zone>/` in the state directory, and start it again. tarn
  issues a new certificate with a new key, within its limit of 4 a week. Revoke
  the old certificate with an ACME client such as
  `lego` and the account key in `production/account.key`.
- **Cloudflare token:** roll it in the Cloudflare dashboard, update the credential
  file, and restart tarn.
- **Page password:** change it from the page, which signs out every other browser.
  If you're locked out, remove `admin_password_hash` from the config file and
  restart with `-admin-password-file`.
- **Records token:** set a new one from the page. Only its hash is stored.
