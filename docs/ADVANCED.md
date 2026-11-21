# tarn: advanced setup and reference

Setting tarn up by hand, using nginx or traefik, apps that sign URLs, and every
option. Most people only need the [quick start](../README.md#quick-start).

## Setup by hand

This is what the wizard does, for a machine set up with flags instead, or with
nginx or traefik. Replace `t.example.com` with your subdomain, and `100.x.y.z` with
the machine's tailnet IP from `tailscale ip -4`.

### 1. Install

From a release, verified against tarn's signing key:

```sh
curl -fsSL https://github.com/elliotnorth/tarn/releases/latest/download/install.sh | sudo sh
```

Or, on Debian or Ubuntu, the `.deb` from the same release, checked against
`SHA256SUMS` (`armhf` for 32-bit Raspberry Pi OS). It runs tarn as a `tarn` system
user, puts the binary in `/usr/bin` (use that path in the `ExecStart` lines below),
and keeps state in `/var/lib/tarn`. It ships no config or secrets, and like the
installer it starts tarn in setup mode (`sudo tarn status` shows the address):

```sh
sudo apt install ./tarn_0.4.1_amd64.deb
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

On Headscale, see [Headscale](#headscale) instead.

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

## Headscale

tarn reads the device list from the Tailscale client, so it works the same on a
[Headscale](https://headscale.net) tailnet. This is new and hasn't been tested on a
real Headscale tailnet yet, so please report what you find.

tarn notices Headscale from the tailnet's DNS domain (anything other than
`*.ts.net`). The setup wizard, `tarn doctor` and the status page then point at
Headscale's config file instead of the Tailscale admin console.

**Split DNS.** Headscale has no admin console, so add the route to its
`config.yaml` (Headscale 0.23 or later), next to any nameservers already there:

```yaml
dns:
  nameservers:
    split:
      t.example.com:
        - 100.x.y.z
```

Restart Headscale, and check from a device with `tailscale dns status`. Devices
need `--accept-dns=true`, which is the default.

**Pick a zone outside `base_domain`.** MagicDNS answers every name under Headscale's
`base_domain` itself, so tarn would never be asked. If `base_domain` is
`hs.example.com`, use `t.example.com`, not `t.hs.example.com`. The wizard and
`tarn doctor` both refuse a zone inside it.

**Renaming devices.** Names come from Headscale, so rename with
`headscale nodes rename`. Two devices with the same name are reported as a name
clash, as on Tailscale.

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
| `-status-name` | `tarn` | Name of the status page on the tailnet, when proxying services. Empty turns it off |
| `-cloudflare-token-file` | | Cloudflare token. Setting it turns on certificates |
| `-services-file` | | Services to proxy on port 443 |
| `-export-dir` | | Also write the certificate here |
| `-admin-password-file` | | Password for changing things from the status page |
| `-config` | | tarn's config file, needed to change settings from the page |
| `-acme-staging` | off | Use Let's Encrypt's staging service |
| `-acme-email` | | Contact address for the ACME account |
| `-state-dir` | `/var/lib/tarn` | Where the account, certificate and key live |

