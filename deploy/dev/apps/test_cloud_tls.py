from datetime import datetime, timedelta, timezone
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import cloud_tls as m


def ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture CA')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=60))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(serialization.Encoding.PEM,
               serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class CloudTlsTests(unittest.TestCase):
    def test_valid_chain_and_exact_dev_hosts(self):
        cert, key = ca()
        values = m.generate(cert, key)
        m.verify(values, cert)
        leaf = x509.load_pem_x509_certificate(values['tls.crt'])
        self.assertEqual(set(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                             .get_values_for_type(x509.DNSName)), set(m.HOSTS))
        self.assertFalse(any('*' in host for host in m.HOSTS))
        self.assertNotIn('heterocloud.mizuame.app', m.HOSTS)

    def test_wrong_ca_or_key_rejected(self):
        cert, key = ca()
        other_cert, other_key = ca()
        values = m.generate(cert, key)
        with self.assertRaises(Exception):
            m.verify(values, other_cert)
        with self.assertRaises(ValueError):
            m.generate(cert, other_key)
        with self.assertRaises(ValueError):
            m.verify({**values, 'tls.key': other_key}, cert)


if __name__ == '__main__':
    unittest.main()
