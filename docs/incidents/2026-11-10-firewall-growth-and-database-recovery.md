# Overlay firewall growth and identity database recovery

On 2026-11-10, HeteroCloud's OIDC discovery endpoint returned HTTP 503.
PostgreSQL on `db-b` was waiting for a synchronous standby while `db-h`
could not start its replica because its WAL timeline had diverged. Control-plane
startup and identity placement consequently failed to make progress.

An independent defect was found in the stopped-node firewall reconciler. When
another controller inserted a rule ahead of its jump, each reconciliation
inserted another jump and left the previous one behind. Across five live nodes,
the three managed chains had accumulated approximately 46,000 duplicate
jumps. While investigating the broken replica, the p5-to-p10 overlay round
trip was approximately 830 ms. After deduplication it was approximately
1.3 ms in a five-packet sample. The measured correlation does not establish
that the firewall was the only cause of the WAL divergence or the incident.

## Recovery

- With `db-b` verified as the running primary, the failed `db-h` standby
  was reinitialized from that primary. The old divergent standby data was
  discarded; the authoritative primary was not reset. Streaming synchronous
  replication and subsecond flush lag were subsequently observed.
- The reconciler now installs one tagged anchor and removes only its own old
  anchors in an atomic firewall restore. The stopped node remains fenced.
  The live rules were deduplicated serially on all five reachable nodes.
- The public OIDC discovery endpoint subsequently returned HTTP 200.
  This check does not by itself prove that every login path or future recovery
  is healthy.

## Reproduction and validation

- The isolated [network-namespace E2E](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/42802064410)
  populated 3,500 duplicates per chain, checked preservation of unrelated
  rules and the stopped-node fence, and verified that a second reconciliation
  does not grow the rules again.
- Unit tests cover fence changes, malformed roster entries, failed restores,
  and already-reconciled rules. The live cleanup was verified to have one
  managed hook per chain immediately after application.
- The node journal budget and firmware-updater idle settings were applied
  serially. A UID-preconditioned cleanup removed 83 old terminal pods and
  69 stale terminating pods on the explicitly stopped node. A six-hour timer
  repeats that limited cleanup.
- As separately authorized for resource reclamation, the three stopped
  `hetero-dev` guests and the running `vercel-research` guest, together
  with their dedicated storage, were removed. Those guest data are gone.

## Remaining risks

- The separate PostgreSQL DCS still has two live voters and one stopped voter.
  Losing either live voter can prevent quorum; this change does not restore
  three-voter failure tolerance.
- Successful replica reinitialization is not a substitute for a tested,
  independent database backup and restore.
- Investigation of the underlying WAL divergence and intermittent network
  problems remains open. Validate live VPN, browser login, and platform
  recovery independently after future infrastructure changes.
