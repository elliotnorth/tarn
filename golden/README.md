# Golden fixtures

Captured `tailscale status --json` output, used as test input for the peer-list
parser. A parser change that breaks one of these files is a bug, and a new
Tailscale version gets its own file, so a format change shows up as a diff.

| File | Tailscale client | Notes |
|------|------------------|-------|
| `status-1.104.5.json` | 1.104.5 (Debian 13 LXC) | **Real Linux capture**, 7 peers. Two phones share HostName `Phone` (MagicDNS `phone`, `phone-1`); a PC with HostName `DESKTOP-0000000` is `pc`; `laptop` is offline. Expected names: tarn, phone, phone-1, ente, laptop, nextcloud, vaultwarden, pc |
| `status-1.104.4.json` | 1.104.4 (Windows) | 6 peers. See "Known quirks" below |
| `status-synthetic-names.json` | Hand-written, 1.104.5 shape | Not a capture. HostName and DNSName differ (renamed PC, two phones with the same OS hostname, one node with no DNSName), as seen on a real tailnet |

## Scrubbing (required before committing a fixture)

Fixtures must never contain real network details. `status-1.104.4.json` was
and `status-1.104.5.json` were scrubbed this way
(1.104.5 uses `nTEST00000NCNTRL` IDs, `example-user1@github`, tailnet name
`example-tailnet-name`):

| Field | Replaced with |
|-------|---------------|
| Tailnet IPv4 (100.64.0.0/10) | `100.64.0.N` (consistent per address) |
| Tailnet IPv6 (`fd7a:115c:a1e0::/48`) | `fd7a:115c:a1e0::N` |
| Public and LAN IPv4 | `192.0.2.N` or `203.0.113.N` (RFC 5737 documentation ranges) |
| Device names that identify a person or hardware | Generic names (`Phone`, `laptop`, `DESKTOP-0000000`), keeping any collisions and renames intact |
| Node keys | `nodekey:000…0N` |
| Stable IDs and NodeIDs | `nTESTNODE0NCNTRL`, `100N` |
| Tailnet name and MagicDNS suffix | `example-tailnet.ts.net` |
| Login, display name, avatar | `example-user`, empty avatar |
| DERP relay region | `relay` |

The same real value always maps to the same fake value, so duplicate and
cross-referenced IPs behave the same as in the original.

## Known quirks in `status-1.104.4.json`

- **Hand-edited before scrubbing.** Every peer is named `peer1`, with
  `DNSName: "peer1"` (no suffix and no trailing dot). That isn't what a real
  client prints, but it is a useful case for the name-collision and
  DNSName/HostName fallback rules.
- **Inconsistent self addresses.** The top-level `TailscaleIPs` and
  `Self.TailscaleIPs` differ, also from the hand edit.
- **Re-serialized.** The capture went through PowerShell and was then
  re-written with 2-space indentation, so whitespace and key order are not
  byte-for-byte what the CLI prints.
- **Not from Linux.** It was captured on Windows; tarn targets Linux.

## Notes on `status-1.104.5.json`

- IPv6 addresses were renumbered to match their IPv4 counterparts, so they
  are no longer derived from the node keys the way real ones are.
- Re-indented after pasting; otherwise as the CLI printed it.
