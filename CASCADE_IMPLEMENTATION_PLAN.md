# Cascade Implementation Plan

## Topology

- `gateway` — entry node and control plane.
- `exit` — remote egress node.

## Routing

- Local domains/zones -> `direct`.
- Other traffic -> `to-exit`.

## Sync

- Master stores remote registry and pushes signed snapshots.
- Remote validates signature and applies user updates idempotently.

## Security

- API allowlist by source node.
- HMAC signatures for sync payloads.
- Service restart only when config actually changed.
