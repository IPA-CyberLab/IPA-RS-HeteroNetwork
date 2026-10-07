# Flash custom domain controller

See [user/API/CLI instructions](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/blob/master/docs/networking/custom-domains.md).

Terraform creates the Argo CD application and enables cert-manager Gateway API support. `site.json` contains site-specific names; the collector itself does not contain a production API endpoint. Two replicas run on uc-k8sp4 and uc-k8sp5, outside the dedicated Secret Manager masters.

The controller verifies CNAME delegation to the requesting service using two public DNS resolvers. Flattened aliases require a service-specific TXT proof and matching public destination addresses. It provisions namespaced Certificates through the HTTP-01 ClusterIssuer and publishes only verified hostnames and their certificates to the gateway bundle. The collector cannot read the DNS-provider credentials or tenant secrets.

The private HTTP-01 Gateway has a TCP 80 listener for cert-manager routes. Public host gateways forward only the challenge path there. HTTPS uses the existing shared application Gateway; custom HTTPRoutes preserve the service's optional OIDC policy and use an individual callback hostname. Adding or removing aliases never changes the FlashService workload spec or its generation.

A resource-version and UID guarded lease plus a writer fence prevent stale replicas from replacing a newer gateway bundle. Unknown DNS responses preserve already verified material. Confirmed delegation changes withdraw the hostname. Certificate renewal retains a working route only while all published origins still present a currently valid, publicly trusted certificate. Finalizers remove owned routes, policies, certificates and Secrets before releasing domain reservations.

```sh
python3 -B -m unittest discover -s deploy/gitops/custom-domains -p 'test_*.py' -v
sudo python3 -B -m unittest discover -s scripts -p test_custom_domain_tls.py -v
```

Limits: eight names per service, 128 names per deployment, 768 KiB TLS bundle, 256 KiB generated gateway configuration. The configured public origins and DNS provider continue to be managed by the existing majority-quorum DNS controller.
