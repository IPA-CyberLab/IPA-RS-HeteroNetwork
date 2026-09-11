# DEV Application Dependencies

`redis-images.json` contains two candidate auxiliary image pins, using the same
`version`/`image` shape as the DEV site's `auxiliary_images`. It is not a complete
site configuration, release-channel change, or automatically applied manifest.

On 2026-09-11, registry inspection returned these multi-architecture manifest
digests. The amd64 child image labels reported version 8.10.1 for both:

- Redis amd64: `sha256:e501488697282e1ba109dae69798543fe70817be085524409fa9c782103e2730`
- Sentinel amd64: `sha256:9a8a5797673606e9a97ce5c8df44bc0051df63210e60e4635f39b049f9cf7559`

Discovery used the upstream tags; configuration retains immutable digests, not
`latest`. Manifest availability and version labels alone do not prove guest
pull access, chart entrypoint compatibility, security patch status or failover.
Do not promote these pins to production based on this inspection.

The environment renderer splits Redis's fully qualified reference into the
Bitnami subchart's separate `registry`, `repository`, `tag` and `digest` fields.
Other charts retain their existing image parameter contracts.

A prospective Helm render on 2026-09-11 against Flow commit `411361c` used
these real image digests with fixture credentials/site values. It emitted three
Redis/Sentinel pods, required host anti-affinity and a new PVC template, with
both container image references exactly matching the pins. This was not the
selected-release deployment check and did not contact Kubernetes.

Authenticated three-pod Sentinel values are now in the DEV Flow overlay, using
the published dev.5 authentication support. Still required: fresh Secret and
LiveKit configuration provisioning, app-only storage capacity and reservations,
actual pull/startup checks, writable-primary discovery and node-loss recovery.
Existing Keycloak identity state must not be reused for application data.

## Storage Reservations

`storage_plan.py` renders an offline, fixed list of 18 local PV reservations and
the non-default `dev-app-local` StorageClass. It does not create directories,
format disks, apply Kubernetes resources, or validate a live cluster identity.
The UID annotation is descriptive, not an admission guard.

Each DEV guest reserves 35 GiB: three 5 GiB application PostgreSQL volumes,
8 GiB for Redis, and separate 2 GiB metadata / 10 GiB data volumes for Garage.
Reservations use exact PVC names and hostname affinity, with `Retain` reclaim
policy. They never reference the existing identity storage paths or class.
The optional Helm contract test compares the reservations with the selected
release charts' StatefulSet claims and the application database renderer.

PV capacity declarations do not impose filesystem quotas. The proposed 64 GiB
guest disks provide a shared filesystem; enforcing individual volume limits
requires an additional quota mechanism. Three guests on one physical host are
not physical-host HA. These manifests must not be applied until dedicated
mounts, directory ownership, cluster identity, and consumer mount dependencies
have been verified operationally.
