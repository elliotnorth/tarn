# tarn

**Real HTTPS names for everything on your tailnet.**

tarn runs on one always-on Linux machine and gives every device and service on your
[Tailscale](https://tailscale.com) or [Headscale](https://headscale.net) network a
name on your own domain:

```
before:  https://nextcloud.tail1234.ts.net
after:   https://nextcloud.t.example.com
```

No ports open to the internet. Certificates renew themselves.

## How it works

- **DNS.** Every 30 seconds tarn reads your device list and answers
  `<device>.<zone>` with that device's tailnet IP. It answers only for your zone and
  never forwards anything else.
- **HTTPS.** tarn gets one wildcard certificate (`*.t.example.com`) from Let's
  Encrypt, renews it, and proxies your services with it.

tarn never changes your tailnet's settings. On its own it only talks to Let's
Encrypt and Cloudflare. It uses about 9 MB of RAM.

## You need

- A Tailscale or Headscale tailnet, and access to its DNS settings
- An always-on Linux machine on it (amd64, arm64 or armv7: a Pi, NAS, VM or LXC),
  with sudo
- Ports 53 and 443 free on that machine's tailnet address
- A domain with its DNS on Cloudflare (the free plan is fine). No domain? See
  [Getting a domain](#getting-a-domain)

No public IP, static IP or port forwarding.

No Tailscale? tarn also runs on plain WireGuard or a LAN. See
[Without Tailscale](docs/ADVANCED.md#without-tailscale-wireguard-or-a-lan).

## Install

1. In Cloudflare, [create an API token](https://dash.cloudflare.com/profile/api-tokens):
   **Create Custom Token**, with **Zone → Zone → Read** and **Zone → DNS → Edit**,
   for your domain only.
2. On the Linux machine, run:

   ```sh
   curl -fsSL https://github.com/elliotnorth/tarn/releases/latest/download/install.sh | sudo sh
   ```

   It prints a setup address and a one-time code. `sudo tarn status` shows them again.
3. Open the setup address from another device on your tailnet. Enter the code, your
   zone (such as `t.example.com`), the Cloudflare token and a password.
4. Add the nameserver the last setup page shows:
   - **Tailscale:** in the [admin console](https://login.tailscale.com/admin/dns),
     under **DNS → Nameservers**, add a custom nameserver with **Restrict to domain** on.
   - **Headscale:** add the lines it shows to Headscale's `config.yaml`, then restart
     Headscale.
5. Open `https://tarn.t.example.com`, sign in, and follow the **Getting started** card
   to switch to a trusted certificate and add your first service.

tarn starts on Let's Encrypt's test certificates, so browsers warn until step 5.
If something doesn't work, run `sudo tarn doctor`. It checks each part and says how
to fix it.

## Everyday use

### Add a service

On the status page, open **Services → Add**. Give it a name and the app's address,
such as `http://100.64.0.5:8080` or `https://nextcloud.tail1234.ts.net`. It works
at `https://<name>.t.example.com` straight away.

Then tell the app its new name, for example Vaultwarden's `DOMAIN` or Nextcloud's
`trusted_domains`. The form shows what to change for common apps. Passkeys are tied
to the old name.

Anyone who can reach tarn can reach every service behind it. Use your tailnet's
access rules to decide who can reach tarn.

### Check on it

```sh
tarn status         # summary: zone, names, certificate, services
sudo tarn doctor    # checks every part and prints a fix for anything wrong
```

The status page is also at `http://127.0.0.1:9580/` on the machine itself.
For Prometheus, add `-metrics` to tarn's command line ([how](docs/ADVANCED.md#changing-tarns-command-line)) and scrape `http://127.0.0.1:9580/metrics`.

### Back up and restore

```sh
sudo tarn backup                                # writes tarn-backup-<date>.tar.gz
sudo systemctl stop tarn
sudo tarn restore tarn-backup-<date>.tar.gz
sudo systemctl start tarn
```

The backup holds the certificate and its private key, settings, services, and the
Cloudflare token saved by setup. Keep it private. Restoring keeps the certificate, so it doesn't count
against Let's Encrypt's limits.

### Update or remove

```sh
sudo tarn update             # latest release; -version v0.4.0 for a given one
sudo tarn uninstall -yes     # keeps certificate and settings; add -purge to delete them
```

`tarn update` checks the release's signature first. If the new version doesn't start,
it puts the old one back. tarn never checks for updates by itself.

Installed from the `.deb`? Update by installing the new `.deb` the same way. Remove
with `sudo apt remove tarn`, or `sudo apt purge tarn` to delete the certificate and
settings too.

After removing tarn, delete its nameserver from your tailnet's DNS settings.

## Troubleshooting

Run `sudo tarn doctor` first. Common problems:

| Problem | Fix |
|---------|-----|
| `address already in use` on port 53 | Another DNS server listens on every address. Limit it (Pi-hole or dnsmasq: `bind-interfaces`) |
| `tailscale is not running` | Run `sudo tailscale up`. tarn retries until it's back |
| `tailnet IP changed` in the log | Update the nameserver in your tailnet's DNS settings to the new IP |
| `dig` works, other devices don't | Check `tailscale dns status` on the device, and that it runs with `--accept-dns=true` |
| Name works in `dig` but not the browser | Turn off the browser's Secure DNS (DNS over HTTPS) |
| Nothing resolves on Android | Turn off Private DNS |
| A device is missing or has the wrong name | Rename it in Tailscale or Headscale. Clashes show on the **Machines** tab |
| `certificate update failed` | Usually the token's permissions. Read `err=` in the log. tarn keeps retrying, and DNS keeps working |
| `502` from a service | The app is down or tarn can't reach it. See `upstream failed` in the log |
| Forgot the page password | See [resetting the password](docs/ADVANCED.md#forgot-the-page-password) |

Offline devices keep resolving, and only A and AAAA records are answered. Both are
on purpose.

## Getting a domain

tarn only needs a subdomain, so a domain you already own works. Point its DNS at
Cloudflare wherever you bought it. Watch renewal prices: most registrars sell the
first year cheap and renew much higher.

| Registrar (.com) | First year | After that | |
|-----------|-----------|------------------|---|
| [Cloudflare](https://www.cloudflare.com/products/registrar/) | ~$11 | ~$11 | Cheapest long-term, nothing to connect |
| [Spaceship](https://www.spaceship.com) | ~$3 with promo | ~$11 | Cheapest first year |
| [Porkbun](https://porkbun.com) | ~$12 | ~$12 | Same price every year |
| [Namecheap](https://www.namecheap.com) | ~$6.50–11 | ~$20 | Pricey renewal |

`.store`, `.online` and `.site` start around $1–3 but renew at $30–44. Prices
checked 2026-11-07.

## More

- [docs/ADVANCED.md](docs/ADVANCED.md): setting up by hand, nginx or traefik, apps
  that sign URLs, Headscale, running without Tailscale, settings and every option
- [SECURITY.md](SECURITY.md): reporting a problem, and what tarn protects against

License: [AGPL-3.0-or-later](LICENSE)
