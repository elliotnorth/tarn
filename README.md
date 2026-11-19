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

## Quick start

1. [Create a Cloudflare token](https://dash.cloudflare.com/profile/api-tokens) with
   **Create Custom Token**: **Zone → Zone → Read** and **Zone → DNS → Edit**, for
   your one domain.
2. On the Linux machine, install tarn. It starts in setup mode and prints an address
   and a one-time code:

   ```sh
   curl -fsSL https://github.com/elliotnorth/tarn/releases/latest/download/install.sh | sudo sh
   ```

3. Open that address from another device on your tailnet. Enter the code, your zone
   (such as `t.example.com`), the token and a password for the status page.
4. In the [Tailscale admin console](https://login.tailscale.com/admin/dns), add the
   nameserver the last page shows, with **Restrict to domain** on.
5. Open `https://tarn.t.example.com`, switch to a trusted certificate, and add your
   services.

`sudo tarn status` shows the address and code again, and `sudo tarn doctor` checks
every step. Setup starts with Let's Encrypt's staging service, so a mistake can't
use up the weekly limit. The browser warns about the certificate until you switch.

For setting it up by hand, nginx or traefik, apps that sign URLs, and every
option, see [docs/ADVANCED.md](docs/ADVANCED.md).

## Everyday use

### Status page

Open `http://127.0.0.1:9580/` on the machine to see machines, services, DNS
totals and the certificate. When tarn proxies services, the page is also at
`https://tarn.t.example.com` from other devices. Its lists and totals need sign-in
or the records token there. Use `-status-name` to give it another name, or
`-status-name ""` to keep it on the machine only. A `tarn` line in the services file
replaces it.

After the setup wizard, changing services and settings from the page is already on.
If you [set tarn up by hand](docs/ADVANCED.md#setup-by-hand):

**To add, change and remove services from the page,** set a password of at least 12
characters and keep the services file where tarn can write to it:

```sh
(umask 077; read -rsp 'password: ' P; printf '%s\n' "$P" | sudo tee /etc/tarn/admin-password >/dev/null; unset P); echo
sudo cp /etc/tarn-services /var/lib/private/tarn/services
```

In `https.conf` (from [step 4](docs/ADVANCED.md#4-get-a-certificate)), add
`LoadCredential=admin:/etc/tarn/admin-password`, and change `ExecStart` to use `-services-file /var/lib/tarn/services -admin-password-file
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
readable by you only. Keep it somewhere private. If you used the setup wizard, the
Cloudflare token is in it too. A token in `/etc/tarn` isn't, so keep a copy of that
file separately.

Restore refuses to run while tarn is running, and it keeps the current state next to
the state directory as `*.before-restore-<time>`. It writes the services file only to
a path you give it with `-services-file`, and only if nothing is there yet. Otherwise it
leaves the file as `restored-services` in the state directory. Only restore backups
you made yourself.

Restoring keeps the certificate, so it doesn't count against Let's Encrypt's limits.

### Update or remove

```sh
sudo tarn update                 # the latest release, or -version v0.4.1 for a given one
sudo tarn uninstall              # lists what it removes; add -yes to do it
```

`tarn update` checks the release's signature and checksum, and that the new binary
runs, before replacing anything. It restarts tarn and waits up to a minute for it to
answer as the new version; if it doesn't, the old binary goes back and tarn restarts
on it. The old binary stays as `tarn.previous`. tarn never checks for updates by
itself.

`tarn uninstall` keeps the certificate, config and `/etc/tarn`; `-purge` deletes them
too. If you built tarn yourself, update with `git pull` and rebuild.

With the `.deb`: `sudo apt remove tarn` keeps the certificate and config, and
`sudo apt purge tarn` deletes them.

If you remove it, delete the nameserver from your tailnet too.

## Troubleshooting

| Symptom | Fix |
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
