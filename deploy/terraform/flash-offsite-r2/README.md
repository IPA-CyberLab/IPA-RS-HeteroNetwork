# Private independent Flash backups

This optional module creates a private Cloudflare R2 bucket outside the Kubernetes
cluster. `prevent_destroy` protects the bucket. Public r2.dev access is explicitly
disabled; no public custom domain is created. Source: Cloudflare provider
[bucket](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.13.0/docs/resources/r2_bucket.md)
and [managed domain](https://github.com/cloudflare/terraform-provider-cloudflare/blob/v5.13.0/docs/resources/r2_managed_domain.md)
contracts. Keep the Terraform backend in a protected operator location.

After applying with a protected `CLOUDFLARE_API_TOKEN`, create an S3 credential
scoped to this bucket's object read/write operations. Store endpoint, bucket,
region (`auto`), access_key and secret_key in an owned 0600 JSON file. Do not paste
credentials into Git, chat, command arguments or Terraform variables.

Run `scripts/configure-flash-offsite.py` using `--config-file`, `--kubeconfig` and
`--recovery-key-file`. It writes the destination Secret without exporting values
and saves the catalog key to the protected recovery file before publishing. Keep
that key in an independent protected recovery location. Re-running preserves it.

Before enabling `backups.offsite.enabled` in the Flash Argo CD application, verify
a copy and an empty-bucket recovery using the provider's `ops/offsite.py`. The
CronJob's transfer/storage limits must fit the budget. Configure R2 cost alerts;
the copier enforces its destination byte cap, while R2 billing remains external.
The module does not enable scheduled exports merely by creating a bucket.
