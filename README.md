# tarn

**Real HTTPS names for everything on your tailnet.**

tarn runs on one always-on Linux machine and gives every device and service on
your [Tailscale](https://tailscale.com) network an address on your own domain:

```
before:  https://nextcloud.tail1234.ts.net
after:   https://nextcloud.t.example.com
```

No ports open to the internet, and no manual certificate work.

It's young. I run it on my own tailnet every day, but expect rough edges, and
[Headscale](https://headscale.net) isn't supported yet. Issues and PRs are welcome.

## How it works

- **DNS.** Every 30 seconds tarn reads your device list and answers
  `<device>.<zone>` with that device's tailnet IP. Only for your zone, and it
  never forwards or guesses.
- **HTTPS.** tarn gets one wildcard certificate (`*.t.example.com`) from Let's
  Encrypt and renews it automatically. It then proxies your services, or hands
  the certificate to nginx or traefik.

tarn never changes your tailnet's settings, opens ports to the internet, or
contacts anything except Let's Encrypt and your DNS provider.

**Runs on** Linux (amd64, arm64, armv7): a Pi, NAS, VPS, VM or container. It used
about 9 MB of RAM and almost no CPU on a real tailnet.

## What you'll need

- A **Tailscale tailnet**, with admin access to its DNS settings
- An **always-on Linux machine** in that tailnet, with sudo
- **Port 53 free** on its tailnet address, and 443 too for the proxy
- For HTTPS: a **domain** with its **DNS on Cloudflare** (free plan is fine). No
  domain? See [Getting a domain](#getting-a-domain)

You don't need a public or static IP, or port forwarding.

## Setup

Replace `t.example.com` with your subdomain, and `100.x.y.z` with the machine's
tailnet IP from `tailscale ip -4`.

### 1. Install

From a release, verified against tarn's signing key:

```sh
curl -fsSL https://github.com/elliotnorth/tarn/releases/latest/download/install.sh | sudo sh
```

Or build it yourself, with Go 1.27 or newer:

```sh
git clone https://github.com/elliotnorth/tarn.git
cd tarn && go build -o tarn . && sudo install tarn /usr/local/bin/tarn
```

### 2. Run it as a service

Create `/etc/systemd/system/tarn.service`:

```ini
[Unit]
Description=tarn: DNS names for your tailnet
After=tailscaled.service network-online.target
Wants=tailscaled.service network-online.target

[Service]
ExecStart=/usr/local/bin/tarn -zone t.example.com
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now tarn
curl http://127.0.0.1:9580/healthz               # "status": "ok"
curl http://127.0.0.1:9580/records               # every name tarn answers
dig @100.x.y.z laptop.t.example.com +short       # that device's 100.x address
```

### 3. Point your tailnet at tarn

In the [Tailscale admin console](https://login.tailscale.com/admin/dns) under
**DNS → Nameservers**, add a **Custom** nameserver `100.x.y.z`, turn on **Restrict
to domain**, and enter `t.example.com`.

From another device, run `ping laptop.t.example.com`. On Windows use `ping` or
`Resolve-DnsName`, because `nslookup` ignores split DNS. Devices are named as in
the admin console, and new ones appear within 30 seconds.

**That's DNS done.** The rest is for HTTPS.

### 4. Get a certificate

[Create a Cloudflare token](https://dash.cloudflare.com/profile/api-tokens) with
**Create Custom Token**: permissions **Zone → Zone → Read** and **Zone → DNS →
Edit**, for your one domain. Never use your global API key. Save it:

```sh
sudo install -d -m700 /etc/tarn
(umask 077; read -rsp 'token: ' T; printf '%s\n' "$T" | sudo tee /etc/tarn/cloudflare-token >/dev/null; unset T); echo
```

List your services in `/etc/tarn-services` (mode 644), one `name upstream-url` per
line. Upstreams can be a `tailscale serve` address or a plain IP and port:

```
vaultwarden https://vaultwarden.tail1234.ts.net
nextcloud   http://100.64.0.5:8080
```

Create `/etc/systemd/system/tarn.service.d/https.conf`:

```ini
[Service]
StateDirectory=tarn
StateDirectoryMode=0700
LoadCredential=cloudflare:/etc/tarn/cloudflare-token
ExecStart=
ExecStart=/usr/local/bin/tarn -zone t.example.com -cloudflare-token-file ${CREDENTIALS_DIRECTORY}/cloudflare -services-file /etc/tarn-services
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart tarn
journalctl -u tarn -n 20 | grep certificate      # "certificate ready"
```

Using this accepts Let's Encrypt's terms. Add `-acme-staging` while experimenting,
because the real service limits repeat certificates to 5 a week. `/healthz` shows
expiry and any renewal error.

- **Everything behind tarn is equally reachable.** Anyone who can reach tarn can
  reach every listed service, and per-device ACLs stop applying to them.
- A listed name resolves to tarn and replaces a device with the same name.
- Tell each app its new name, such as Vaultwarden's `DOMAIN` or Nextcloud's
  `trusted_domains` and `overwritehost`. Passkeys and security keys are tied to
  the old name.
- Changes made by hand to the services file need a restart.
- Plain `http://` upstreams must be on the tailnet, a private LAN or this machine.
  Anything else would be unencrypted, so tarn refuses it.

### Using nginx or traefik instead

Replace `-services-file` with `-export-dir`, and tarn writes `cert.pem` and
`key.pem` there, readable by one group:

```sh
sudo groupadd --system tarn-certs && sudo usermod -aG tarn-certs www-data
sudo install -d -m 2770 -g tarn-certs /etc/tarn-export
```

Add `SupplementaryGroups=tarn-certs`, `ReadWritePaths=/etc/tarn-export` and
`-export-dir /etc/tarn-export` to `https.conf`. Reload your web server when
`cert.pem` changes, for example with a systemd `.path` unit.

### Apps that sign URLs (S3, MinIO, Ente)

Normally tarn rewrites the host, which breaks links signed for a name. For these apps
add `host=preserve`, or tick **Preserve host** on the Services tab:

```
ente-photos  http://100.64.0.5:3200  host=preserve
```

tarn then forwards the host, path and query byte for byte. Use it only for apps that
sign URLs: most apps behind `tailscale serve` need the default.

- **tarn still decrypts the traffic.** It only leaves the request unchanged.
- **The storage port becomes reachable on the tailnet,** not just inside its container.
  Signatures still protect the data, but on a shared tailnet add an ACL for it.
- **Plain HTTP is only encrypted over the tailnet.** On a LAN address anyone on that
  network can read the traffic and the signed links, so prefer the tailnet address.
- **Binding Docker to `0.0.0.0` opens the port on your LAN,** and Docker's published
  ports skip ordinary `ufw` rules. Bind the tailnet IP, or filter in `DOCKER-USER`.
- Signed links for the old name stop working, and apps need to sign in again.

### Status page

Open `http://127.0.0.1:9580/` on the machine to see machines, services, DNS
totals and the certificate. To see it from other devices, add this to the services
file and open `https://tarn.t.example.com`:

```
tarn http://127.0.0.1:9580
```

Everyone on the tailnet can then open it, so use `-records-token-file` if the
machine and service lists shouldn't be visible to them all.

**To add, change and remove services from the page,** set a password of at least 12
characters and keep the services file where tarn can write to it:

```sh
(umask 077; read -rsp 'password: ' P; printf '%s\n' "$P" | sudo tee /etc/tarn/admin-password >/dev/null; unset P); echo
sudo cp /etc/tarn-services /var/lib/private/tarn/services
```

In `https.conf`, add `LoadCredential=admin:/etc/tarn/admin-password`, and change
`ExecStart` to use `-services-file /var/lib/tarn/services -admin-password-file
${CREDENTIALS_DIRECTORY}/admin`. Changes apply at once, with no restart.

- **That password can repoint any service name on your tailnet.** Use a strong one.
- Saving from the page rewrites the file, so comments in it are lost.
- Machines come from Tailscale, so manage those in its admin console.
- Through the proxy, everything except the page itself needs sign-in or the records
  token. `/healthz` stays open on the machine for monitoring.

**To change settings from the page,** add `-config /var/lib/tarn/config`. On first
start, tarn writes that file from your current flags. Flags you pass still win, and
the page shows those as "Set on the command line". To hand one over to the page,
start once with `-config`, then remove that flag and restart.

| Setting | How it applies |
|---------|----------------|
| Answer lifetime, refresh interval, device list source, contact email, records token | Immediately |
| Zone, DNS address, staging or production, page password | Undone after 60 seconds unless you press **Keep** |

The page previews risky changes first. A zone change needs a Cloudflare token that
can edit the new zone, and uses one of Let's Encrypt's 5 certificates a week for that
name. After you press Keep, change split DNS in the Tailscale admin console yourself.
The History tab keeps the last 50 changes, and most can be undone.

**Can't be changed from the page:** the tailscale binary and socket, the management
address, the state directory, the services and export paths, and the Cloudflare token.
Those decide what tarn runs and where it writes, so someone who gets the page password
still can't take over the machine.

Forgot the page password? Delete `admin_password_hash` from the config file and
restart, and the password in `-admin-password-file` works again.

### Check on it

`tarn status` gives a summary. `sudo tarn doctor` checks the TUN device, Tailscale,
port 53, split DNS, the certificate, the Cloudflare token, each service and the clock,
and prints a fix for anything wrong. The token check creates and deletes one TXT record.

For Prometheus, add `-metrics` and scrape `http://127.0.0.1:9580/metrics`. It has the
same totals as `/healthz`: record count, refresh age and failures, DNS replies by
outcome, and certificate expiry and renewal failures. It never has device names or
client addresses. Like `/healthz`, it is open on loopback and needs sign-in or the
records token through the proxy.

### Back up and restore

```sh
sudo tarn backup                       # writes tarn-backup-<date>.tar.gz here
sudo systemctl stop tarn
sudo tarn restore tarn-backup-<date>.tar.gz
sudo systemctl start tarn
```

The backup holds the state directory (certificates, keys, the ACME account, settings
and history) and the services file. **It includes private keys**, so it's written
readable by you only. Keep it somewhere private. The Cloudflare token isn't in it, so
keep a copy of that file separately.

Restore refuses to run while tarn is running, and it keeps the current state next to
the state directory as `*.before-restore-<time>`. It writes the services file only to
a path you give it with `-services-file`, and only if nothing is there yet. Otherwise it
leaves the file as `restored-services` in the state directory. Only restore backups
you made yourself.

Restoring keeps the certificate, so it doesn't count against Let's Encrypt's limits.

### Update or remove

```sh
cd tarn && git pull && go build -o tarn . && sudo install tarn /usr/local/bin/tarn && sudo systemctl restart tarn
sudo systemctl disable --now tarn && sudo rm -r /etc/systemd/system/tarn.service* /usr/local/bin/tarn   # remove
```

If you remove it, delete the nameserver from your tailnet too.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `address already in use` on 53 | Another DNS server listens on all addresses. Limit it (Pi-hole/dnsmasq `bind-interfaces`), or use `-listen` |
| `permission denied` on 53 | Run tarn through its systemd service, which has the permission |
| `tailscale is not running` | Run `sudo tailscale up`. systemd keeps retrying until it's back |
| Not sure what's wrong | Run `sudo tarn doctor`. It checks each part and prints the fix |
| `tailnet IP changed` in the log | tarn restarted on the new IP. Update the nameserver in the admin console |
| `/healthz` says `stale` | tarn can't read Tailscale. `last_error` says why |
| Works with `dig` but not from other devices | Check split DNS with `tailscale dns status`, and that the device has `--accept-dns=true` |
| Name resolves, but not in the browser | Turn off the browser's Secure DNS / DNS over HTTPS |
| Nothing resolves on Android | Turn off Private DNS |
| Wrong name or a device is missing | Rename it in the admin console. Check `collisions` and `skipped` in `/healthz` |
| `certificate update failed` | Read `err=`. It's usually the token's permissions. tarn retries with backoff and DNS keeps working |
| `403 request refused` from a script | State-changing requests need the header `X-Tarn-Request: 1`, which the page sends. Without it, even a wrong password gets 403 instead of 401 |
| Status page says `Signed out` | Through the proxy, everything needs sign-in. On the machine itself it's open |
| `502` from a service | The upstream is down or unreachable from tarn. See `upstream failed` in the log |

Offline devices keep resolving, and record types other than A and AAAA are
refused. Both are intended.

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `-zone` | *(required)* | The subdomain to serve |
| `-listen` | tailnet IPv4, port 53 | DNS address |
| `-source` | `cli` | `cli`, or `localapi` to read tailscaled's socket (less CPU on tiny hosts) |
| `-tailscale` | `tailscale` | Path to the binary, for `cli` |
| `-socket` | `/var/run/tailscale/tailscaled.sock` | Socket, for `localapi` |
| `-interval` | `30s` | How often to re-read the device list |
| `-ttl` | `60` | Seconds answers may be cached |
| `-mgmt` | `127.0.0.1:9580` | Status address, loopback only |
| `-records-token-file` | | Require this bearer token on `/records` |
| `-metrics` | off | Serve Prometheus metrics at `/metrics` on the status address |
| `-cloudflare-token-file` | | Cloudflare token. Setting it turns on certificates |
| `-services-file` | | Services to proxy on port 443 |
| `-export-dir` | | Also write the certificate here |
| `-admin-password-file` | | Password for changing things from the status page |
| `-config` | | tarn's config file, needed to change settings from the page |
| `-acme-staging` | off | Use Let's Encrypt's staging service |
| `-acme-email` | | Contact address for the ACME account |
| `-state-dir` | `/var/lib/tarn` | Where the account, certificate and key live |

## Getting a domain

tarn only needs a subdomain, so a domain you already own works. Most registrars
sell the first year for $1–5 and then renew much higher, so check the renewal
price. Wherever you buy, point its DNS at Cloudflare.

| Registrar (.com) | First year | After that | |
|-----------|-----------|------------------|---|
| [Cloudflare](https://www.cloudflare.com/products/registrar/) | ~$11 | ~$11 | At cost, cheapest long-term, nothing to connect |
| [Spaceship](https://www.spaceship.com) | ~$3 with promo | ~$11 | Cheapest first year |
| [Porkbun](https://porkbun.com) | ~$12 | ~$12 | Same price every year |
| [Namecheap](https://www.namecheap.com) | ~$6.50–11 | ~$20 | Pricey renewal |

Endings like `.store`, `.online` and `.site` start around $1–3 but renew at $30–44.
`.xyz` starts at $1–2 and renews at $11–21. Prices checked 2026-11-07.

## More

Found a security problem? See [SECURITY.md](SECURITY.md).

tarn only looks at your tailnet and never changes it, follows the DNS rules
exactly, and doesn't phone home.

License: [AGPL-3.0-or-later](LICENSE)
