# Pinned geohash relay routing

Enable the embedded, release-pinned Swift/Android directory policy explicitly:

```json
{
  "joined_geohashes": ["gcpvj"],
  "geo_relays": {
    "mode": "supplement",
    "overrides": []
  }
}
```

`supplement` prioritises the explicit overrides and fills the remaining slots
with the pinned nearest-five union. `replace` uses only the overrides and
requires at least one. Each cell has at most ten relays; pinned mode permits
at most eight joined cells. Override URLs are limited to 256 bytes and ten
entries, reject duplicate canonical endpoints, credentials, query strings and
fragments, and require WSS except for numeric loopback test endpoints.

Omitting `geo_relays` preserves the existing fixed `relays` behaviour. Enabling
it routes geohash subscriptions and sends through separate per-cell pools;
the legacy pool no longer receives geohash filters or geohash publishes.
Private mailbox, NIP-17 inbox, profile, NIP-65 and NIP-29 room policies are not
populated from the geographic directories. No directory is downloaded at runtime.

The daemon re-evaluates pool health every 30 seconds. Disconnected/stopped
endpoints are temporarily excluded so the next-nearest candidates can enter.
Failed candidates become eligible again after five minutes; a `replace` policy
never falls back to a public snapshot. If no candidate remains, sends fail
rather than claiming storage. Pools are replaced only when their endpoint set
changes, and the old pool is shut down before the replacement is started.

Join/leave and joined-cell SIGHUP changes update the desired cell set. A join
acknowledges the requested membership; it does not certify relay connectivity.
Changing `geo_relays` policy or override URLs requires a restart, just like
changing the existing fixed relay lists. Invalid reloads retain prior config.

`omachat-ctl status --json` includes `geo_relays` with the mode, exact profile
and both SHA-256 snapshot hashes. `runtime` is null until the service starts.
Once started, `requested_cells` and actual `cells` distinguish desired state
from configured pools. Each cell reports selected endpoints, `pool_active`,
the first ten skipped unhealthy endpoints and their total count. An active
pool is not an assertion that every socket is connected; successful sends
still require a healthy relay acknowledgement.

Shutdown and panic quiesce the geographic pools. No protocol keys, message
contents or new persistent state are stored in the selection diagnostics.
