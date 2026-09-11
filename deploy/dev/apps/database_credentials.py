"""Build DEV database connection material in memory; never print or apply it.

The caller must first verify the live DEV cluster identity and obtain these
Secrets through its authenticated Kubernetes connection. Returned credentials
belong only in the application's complete Secret, not logs or Git.
"""
import base64
import binascii
from urllib.parse import quote, urlencode


DATABASES = {
    "heterocloud-dev": "heterocloud_dev",
    "heterocloud-flow-dev": "heterocloud_flow_dev",
    "heterocloud-syouyu-dev": "heterocloud_syouyu_dev",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def field(secret, key):
    try:
        encoded = secret["data"][key]
        require(isinstance(encoded, str) and len(encoded) <= 131072, "invalid Secret field")
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (KeyError, TypeError, UnicodeError, binascii.Error):
        raise ValueError("invalid or missing Secret field") from None


def connection_material(namespace, credentials, ca):
    require(namespace in DATABASES, "not an application DEV namespace")
    for secret, name in ((credentials, "dev-postgres-app"), (ca, "dev-postgres-ca")):
        require(secret.get("kind") == "Secret" and secret.get("apiVersion") == "v1",
                "expected Kubernetes Secret")
        metadata = secret.get("metadata", {})
        require(metadata.get("namespace") == namespace and metadata.get("name") == name
                and not metadata.get("deletionTimestamp"), "Secret identity mismatch")
    require(credentials.get("type") == "kubernetes.io/basic-auth", "wrong credential type")
    database = DATABASES[namespace]
    username, password = field(credentials, "username"), field(credentials, "password")
    require(username == database and field(credentials, "user") == username
            and field(credentials, "dbname") == database, "database or owner mismatch")
    require(field(credentials, "port") == "5432", "unexpected database port")
    hostname = f"dev-postgres-rw.{namespace}.svc.cluster.local"
    require(field(credentials, "host") in ("dev-postgres-rw", f"dev-postgres-rw.{namespace}",
            f"dev-postgres-rw.{namespace}.svc", hostname), "unexpected database service")
    require(password and len(password.encode("utf-8")) <= 4096 and "\x00" not in password,
            "invalid database password")
    certificate = field(ca, "ca.crt")
    require(certificate.strip().startswith("-----BEGIN CERTIFICATE-----")
            and certificate.strip().endswith("-----END CERTIFICATE-----")
            and "PRIVATE KEY" not in certificate, "expected public CA PEM")
    # Ignore generated URI options and construct the fixed DEV target explicitly.
    url = (f"postgresql://{quote(username, safe='')}:{quote(password, safe='')}@"
           f"{hostname}:5432/{quote(database, safe='')}?"
           + urlencode({"sslmode": "verify-full"}))
    return {"database-url": url, "ca.crt": certificate}
