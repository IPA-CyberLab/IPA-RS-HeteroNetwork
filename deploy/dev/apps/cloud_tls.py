"""Private DEV serving certificate material. No network or filesystem effects."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOSTS = ('dev.heterocloud.mizuame.app', 'heterocloud-dev',
         'heterocloud-dev.heterocloud-dev', 'heterocloud-dev.heterocloud-dev.svc',
         'heterocloud-dev.heterocloud-dev.svc.cluster.local')


def active(cert, now):
    if not (cert.not_valid_before.replace(tzinfo=timezone.utc) <= now
            and cert.not_valid_after.replace(tzinfo=timezone.utc) > now + timedelta(days=1)):
        raise ValueError('DEV certificate is not valid for another day')


def generate(ca_pem, ca_key_pem):
    ca = x509.load_pem_x509_certificate(ca_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    now = datetime.now(timezone.utc)
    active(ca, now)
    if (not isinstance(ca_key, rsa.RSAPrivateKey)
            or ca_key.public_key().public_numbers() != ca.public_key().public_numbers()
            or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign):
        raise ValueError('Wrong DEV CA material')
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTS[0])]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(min(now + timedelta(days=30), ca.not_valid_after.replace(tzinfo=timezone.utc)))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in HOSTS]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return {'tls.crt': cert.public_bytes(serialization.Encoding.PEM) + ca_pem,
            'tls.key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()), 'ca.crt': ca_pem}


def verify(material, ca_pem):
    ca = x509.load_pem_x509_certificate(ca_pem)
    cert = x509.load_pem_x509_certificate(material['tls.crt'])
    key = serialization.load_pem_private_key(material['tls.key'], password=None)
    now = datetime.now(timezone.utc)
    active(ca, now)
    active(cert, now)
    if (cert.issuer != ca.subject or material['ca.crt'] != ca_pem
            or material['tls.crt'] != cert.public_bytes(serialization.Encoding.PEM) + ca_pem
            or cert.public_key().public_numbers() != key.public_key().public_numbers()
            or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value !=
               x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
            or set(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) !=
               {x509.DNSName(host) for host in HOSTS}):
        raise ValueError('DEV serving certificate contract differs')
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
