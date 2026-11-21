# tarn: advanced setup and reference

Most people only need the [install steps](../README.md#install). This page covers
everything else.

- [Changing tarn's command line](#changing-tarns-command-line)
- [Setup by hand](#setup-by-hand)
- [Using nginx or traefik instead](#using-nginx-or-traefik-instead)
- [Apps that sign URLs (S3, MinIO, Ente)](#apps-that-sign-urls-s3-minio-ente)
- [Headscale](#headscale)
- [Without Tailscale (WireGuard or a LAN)](#without-tailscale-wireguard-or-a-lan)
- [The status page](#the-status-page)
- [Forgot the page password](#forgot-the-page-password)
- [Options](#options)

## Changing tarn's command line

To add a flag such as `-metrics`, see the current command with
`systemctl cat tarn`, then run `sudo systemctl edit tarn` and add:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tarn -config /var/lib/tarn/config -metrics
```

Use `/usr/bin/tarn` if you installed the `.deb`. Then run
`sudo systemctl restart tarn`.

## Setup by hand

Use this instead of the setup page if you want flags instead of the wizard, or nginx
or traefik. Replace `t.example.com` with your subdomain, and `100.x.y.z` with the
machine's tailnet IP from `tailscale ip -4`.

### 1. Install

Pick one:

- **Installer** (checks the release signature):

  ```sh
  curl -fsSL https://github.com/elliotnorth/tarn/releases/latest/download/install.sh | sudo sh
  ```

- **`.deb`** for Debian or Ubuntu, from the same release (`armhf` for 32-bit
  Raspberry Pi OS). Check it against `SHA256SUMS`, then:

  ```sh
  sudo apt install ./tarn_<version>_amd64.deb
  ```

  It runs tarn as a `tarn` user, puts the binary in `/usr/bin` (use that path below)
  and keeps state in `/var/lib/tarn`.

- **Build it** with Go 1.27 or newer:

  ```sh
  git clone https://github.com/elliotnorth/tarn.git
  cd tarn && go build -o tarn . && sudo install tarn /usr/local/bin/tarn
  ```

The installer and the `.deb` start tarn on the setup page. Replace their
`/etc/systemd/system/tarn.service` with the one below.

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

Start it and check:

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now tarn
curl http://127.0.0.1:9580/healthz               # "status": "ok"
curl http://127.0.0.1:9580/records               # every name tarn answers
dig @100.x.y.z laptop.t.example.com +short       # that device's 100.x address
```

### 3. Point your tailnet at tarn

- **Tailscale:** in the [admin console](https://login.tailscale.com/admin/dns), under
  **DNS → Nameservers**, add a **Custom** nameserver `100.x.y.z`, turn on **Restrict
  to domain**, and enter `t.example.com`.
- **Headscale:** see [Headscale](#headscale).

From another device, run `ping laptop.t.example.com`. On Windows use `ping` or
`Resolve-DnsName`, because `nslookup` ignores split DNS. New devices appear within
30 seconds.

That's DNS done. The rest is for HTTPS.

### 4. Get a certificate

Create a Cloudflare token as in the [install steps](../README.md#install), and save it:

```sh
sudo install -d -m700 /etc/tarn
(umask 077; read -rsp 'token: ' T; printf '%s\n' "$T" | sudo tee /etc/tarn/cloudflare-token >/dev/null; unset T); echo
```

List your services in `/etc/tarn-services` (mode 644), one `name address` per line:

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

This accepts Let's Encrypt's terms. Add `-acme-staging` while you experiment:
Let's Encrypt allows only 5 certificates a week for the same name.

- A service name replaces any device with the same name.
- Tell each app its new name (Vaultwarden's `DOMAIN`, Nextcloud's `trusted_domains`
  and `overwritehost`).
- Restart tarn after editing the services file by hand.
- Plain `http://` addresses must be on the tailnet, a private LAN or this machine.

### 5. Change things from the status page (optional)

Set a page password of at least 12 characters, and move the services file where
tarn can write it:

```sh
(umask 077; read -rsp 'password: ' P; printf '%s\n' "$P" | sudo tee /etc/tarn/admin-password >/dev/null; unset P); echo
sudo cp /etc/tarn-services /var/lib/private/tarn/services
```

In `https.conf`, add `LoadCredential=admin:/etc/tarn/admin-password`, and change
`ExecStart` to:

```
ExecStart=/usr/local/bin/tarn -config /var/lib/tarn/config -zone t.example.com -cloudflare-token-file ${CREDENTIALS_DIRECTORY}/cloudflare -services-file /var/lib/tarn/services -admin-password-file ${CREDENTIALS_DIRECTORY}/admin
```

Flags on the command line always win over the page. To let the page manage a
setting, start once with the flag and `-config`, then remove the flag and restart.

## Using nginx or traefik instead

Replace `-services-file` with `-export-dir`, and tarn writes `cert.pem` and `key.pem`
there, readable by one group:

```sh
sudo groupadd --system tarn-certs && sudo usermod -aG tarn-certs www-data
sudo install -d -m 2770 -g tarn-certs /etc/tarn-export
```

Add `SupplementaryGroups=tarn-certs`, `ReadWritePaths=/etc/tarn-export` and
`-export-dir /etc/tarn-export` to `https.conf`. Reload your web server when
`cert.pem` changes, for example with a systemd `.path` unit.

## Apps that sign URLs (S3, MinIO, Ente)

tarn normally rewrites the host, which breaks links signed for a name. For these
apps, add `host=preserve`, or tick **Preserve host** on the Services tab:

```
ente-photos  http://100.64.0.5:3200  host=preserve
```

tarn then forwards the request unchanged. Use it only for apps that sign URLs.

- **The storage port must be reachable on the tailnet.** On a shared tailnet, limit
  it with an access rule.
- **Use the tailnet address, not a LAN address.** Plain HTTP on a LAN can be read by
  anyone on it.
- **Docker ports bound to `0.0.0.0` are open on your LAN** and skip `ufw`. Bind the
  tailnet IP, or filter in `DOCKER-USER`.
- Signed links for the old name stop working, and apps need to sign in again.

## Headscale

tarn works the same on Headscale. It recognizes Headscale from the tailnet's DNS
domain, and the setup page and `tarn doctor` then show Headscale instructions.

**Split DNS.** Add this to Headscale's `config.yaml` (Headscale 0.23 or newer), next
to any nameservers already there, and restart Headscale:

```yaml
dns:
  nameservers:
    split:
      t.example.com:
        - 100.x.y.z
```

Check it from a device with `tailscale dns status`. Devices need
`--accept-dns=true`, which is the default.

**Pick a zone outside `base_domain`.** Headscale answers every name under its
`base_domain` itself. If `base_domain` is `hs.example.com`, use `t.example.com`, not
`t.hs.example.com`.

**Rename devices** with `headscale nodes rename`.

## Without Tailscale (WireGuard or a LAN)

tarn can run with no Tailscale at all, for example on a plain WireGuard hub or a
home LAN. It then serves the names in the services file, plus any devices you list
in a hosts file. Certificates work exactly the same.

Add these to tarn's command line (see
[Changing tarn's command line](#changing-tarns-command-line)), using the machine's
own address in place of `192.168.1.10`:

```
-source none -listen 192.168.1.10:53 -proxy-listen 192.168.1.10 -answer 192.168.1.10
```

| Flag | What it does |
|------|--------------|
| `-source none` | Don't read a device list from Tailscale |
| `-listen` | The address to answer DNS on |
| `-proxy-listen` | The address for HTTPS (port 443 unless you give one) |
| `-answer` | The IPv4 address service names resolve to, usually the same machine |
| `-hosts-file` | Optional. Devices to answer for, one `name address` per line |

A hosts file looks like this. tarn re-reads it on every refresh, so changes need no
restart:

```
# name     addresses
laptop     10.8.0.2
nas        192.168.1.20  fd00::20
```

**Point your DNS at tarn for the zone only.** tarn answers only its own zone and
refuses everything else, so it can't be your devices' only DNS server. Forward the
zone to it from the DNS server they already use:

- dnsmasq or Pi-hole: `server=/t.example.com/192.168.1.10`
- Unbound: a `forward-zone` for `t.example.com` with `forward-addr: 192.168.1.10`

WireGuard clients then use that DNS server (`DNS = ` in their config), not tarn.

**Upstreams:** use LAN or WireGuard addresses in the services file, such as
`http://192.168.1.20:8080`. `ts.net` names stop working without Tailscale.

### Moving from Tailscale

tarn can answer on both networks while you move devices over. Keep Tailscale
running, and add:

```
-listen-extra 192.168.1.10:53 -proxy-listen tailnet,192.168.1.10
```

`tailnet` stands for the tailnet IP. tarn now answers DNS and HTTPS on both
addresses. Service names still resolve to the tailnet IP until you add `-answer`,
so devices on WireGuard need `-answer 192.168.1.10`. A name resolves to one place,
so switch `-answer` when most devices have moved.

When everything has moved, change to the `-source none` line above and stop
Tailscale. The certificate stays as it is, and nothing is issued again.

These settings can also go in the config file as `listen_extra`, `proxy_listen`,
`answer`, `hosts_file` and `source`. Flags win over the file, and the status page
can't change them.

## The status page

It's at `https://tarn.t.example.com` on the tailnet, and `http://127.0.0.1:9580/` on
the machine. Through the tailnet it needs sign-in. Use `-status-name` to give it
another name, or `-status-name ""` to keep it on the machine only.

Settings you can change on the page:

| Setting | How it applies |
|---------|----------------|
| Answer lifetime, refresh interval, device list source, contact email, records token | At once |
| Zone, DNS address, staging or production, page password | Undone after 60 seconds unless you press **Keep** |

After changing the zone or DNS address, update split DNS in your tailnet's settings.
The **History** tab keeps the last 50 changes, and most can be undone.

The page can't change the tailscale path and socket, the management address, the
state directory, file paths or the Cloudflare token. Those decide what tarn runs and
where it writes, so someone with the page password still can't take over the machine.

Saving services from the page rewrites the services file, so comments in it are lost.

## Forgot the page password

1. Save a new password:

   ```sh
   sudo install -d -m700 /etc/tarn
   (umask 077; read -rsp 'password: ' P; printf '%s\n' "$P" | sudo tee /etc/tarn/admin-password >/dev/null; unset P); echo
   ```

2. Run `sudo systemctl edit tarn`, and add `LoadCredential=admin:/etc/tarn/admin-password`
   and `-admin-password-file ${CREDENTIALS_DIRECTORY}/admin` to the command line (see
   [Changing tarn's command line](#changing-tarns-command-line)).
3. Stop tarn, remove the `admin_password_hash` entry from `/var/lib/tarn/config`,
   and start tarn again.

## Options

| Flag | Default | What it does |
|------|---------|--------------|
| `-zone` | *(required)* | The subdomain to serve |
| `-listen` | tailnet IPv4, port 53 | DNS address |
| `-listen-extra` | | More DNS addresses, comma-separated. `tailnet` is the tailnet IP |
| `-source` | `cli` | `cli`, `localapi` to read tailscaled's socket (less CPU on tiny hosts), or `none` for no Tailscale |
| `-hosts-file` | | Devices to answer for, one `name address...` per line |
| `-tailscale` | `tailscale` | Path to the binary, for `cli` |
| `-socket` | `/var/run/tailscale/tailscaled.sock` | Socket, for `localapi` |
| `-interval` | `30s` | How often to re-read the device list |
| `-ttl` | `60` | Seconds answers may be cached |
| `-mgmt` | `127.0.0.1:9580` | Status address, loopback only |
| `-records-token-file` | | Require this bearer token on `/records` |
| `-metrics` | off | Serve Prometheus metrics at `/metrics` on the status address |
| `-status-name` | `tarn` | Name of the status page on the tailnet. Empty turns it off |
| `-cloudflare-token-file` | | Cloudflare token. Setting it turns on certificates |
| `-services-file` | | Services to proxy on port 443 |
| `-proxy-listen` | tailnet IPv4, port 443 | HTTPS addresses, comma-separated. `tailnet` is the tailnet IP |
| `-answer` | tailnet IPv4 | IPv4 addresses that service names resolve to |
| `-export-dir` | | Also write the certificate here |
| `-admin-password-file` | | Password for changing things from the status page |
| `-config` | | tarn's config file, needed to change settings from the page |
| `-acme-staging` | off | Use Let's Encrypt's staging service |
| `-acme-email` | | Contact address for the ACME account |
| `-state-dir` | `/var/lib/tarn` | Where the account, certificate and key live |
