"""Cluster identity: a private CA, node certificates and join tokens.

Nodes talk to each other only over mutual TLS with certificates from the
cluster CA. A new node joins in one of two ways:

* With a join token ``opstend1.<ca-fingerprint>.<secret>``. The node checks the
  CA fingerprint before it trusts the cluster and proves knowledge of the
  secret with an HMAC over its certificate request. Tokens expire and work once.
* Through discovery. The pending node announces its public key. An operator
  compares the six-digit pairing code shown on both sides and approves it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TOKEN_PREFIX = "opstend1"  # noqa: S105 - a format marker, not a secret


class EnrollmentError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_fingerprint(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> str:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def pairing_code(ca_fingerprint: str, node_fingerprint: str) -> str:
    """Six digits both sides can display and compare."""
    digest = hashlib.sha256(f"{ca_fingerprint}:{node_fingerprint}".encode()).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def make_csr(key: ec.EllipticCurvePrivateKey, node_id: str, addresses: list[str]) -> bytes:
    sans: list[x509.GeneralName] = [x509.DNSName(node_id)]
    for addr in addresses:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(addr)))
        except ValueError:
            sans.append(x509.DNSName(addr))
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


@dataclass
class IssuedToken:
    token: str
    expires_at: datetime


class ClusterCA:
    def __init__(self, cert_pem: bytes, key_pem_bytes: bytes) -> None:
        self.cert_pem = cert_pem
        self.cert = x509.load_pem_x509_certificate(cert_pem)
        loaded = serialization.load_pem_private_key(key_pem_bytes, password=None)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise EnrollmentError("cluster CA key must be an EC key")
        self.key = loaded
        self.fingerprint = fingerprint(cert_pem)
        self._tokens: dict[str, datetime] = {}

    @classmethod
    def create(cls, cluster_name: str, days: int = 3650) -> ClusterCA:
        key = new_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"OpsTend CA {cluster_name}")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(cert.public_bytes(serialization.Encoding.PEM), key_pem(key))

    def key_pem(self) -> bytes:
        return key_pem(self.key)

    # -- tokens ----------------------------------------------------------

    def issue_token(self, ttl_minutes: int = 30, address: str | None = None) -> IssuedToken:
        secret = secrets.token_bytes(24)
        expires = datetime.now(UTC) + timedelta(minutes=ttl_minutes)
        self._tokens[hashlib.sha256(secret).hexdigest()] = expires
        token = f"{TOKEN_PREFIX}.{self.fingerprint[:32]}.{_b64(secret)}"
        if address:
            token += f".{_b64(address.encode())}"
        return IssuedToken(token, expires)

    def remember_token(self, secret_hash: str, expires: datetime) -> None:
        """Accept a token issued by another voter (tokens are replicated)."""
        self._tokens[secret_hash] = expires

    @staticmethod
    def parse_token(token: str) -> tuple[str, bytes]:
        parts = token.strip().split(".")
        if len(parts) not in (3, 4):
            raise EnrollmentError("malformed join token")
        prefix, fp, secret = parts[:3]
        if prefix != TOKEN_PREFIX or len(fp) != 32:
            raise EnrollmentError("malformed join token")
        return fp, _unb64(secret)

    @staticmethod
    def token_address(token: str) -> str | None:
        """The address of the node that issued the token, if the token carries one."""
        parts = token.strip().split(".")
        return _unb64(parts[3]).decode() if len(parts) == 4 else None

    @staticmethod
    def secret_hash(token: str) -> str:
        return hashlib.sha256(ClusterCA.parse_token(token)[1]).hexdigest()

    @staticmethod
    def proof(secret: bytes, csr_pem: bytes) -> str:
        return hmac.new(secret, csr_pem, hashlib.sha256).hexdigest()

    def redeem(self, csr_pem: bytes, proof: str, secret_hash: str) -> bytes:
        expires = self._tokens.get(secret_hash)
        if expires is None or expires < datetime.now(UTC):
            raise EnrollmentError("join token is unknown, used or expired")
        # The caller verified the proof with the secret it holds for this hash.
        del self._tokens[secret_hash]
        return self.sign(csr_pem)

    def enroll_with_token(self, csr_pem: bytes, token: str, proof: str) -> bytes:
        fp, secret = self.parse_token(token)
        if not hmac.compare_digest(fp, self.fingerprint[:32]):
            raise EnrollmentError("token belongs to another cluster")
        if not hmac.compare_digest(self.proof(secret, csr_pem), proof):
            raise EnrollmentError("token proof does not match the request")
        return self.redeem(csr_pem, proof, hashlib.sha256(secret).hexdigest())

    # -- certificates ----------------------------------------------------

    def sign(self, csr_pem: bytes, days: int = 90) -> bytes:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise EnrollmentError("certificate request signature is invalid")
        node_id = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            san = x509.SubjectAlternativeName([x509.DNSName(str(node_id))])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def verify_node_cert(self, cert_pem: bytes) -> str:
        """Return the node id if the certificate was issued by this CA and is valid."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        try:
            cert.verify_directly_issued_by(self.cert)
        except Exception as exc:
            raise EnrollmentError("certificate was not issued by this cluster") from exc
        now = datetime.now(UTC)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise EnrollmentError("certificate is expired or not yet valid")
        return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

    @staticmethod
    def needs_renewal(cert_pem: bytes, within_days: int = 30) -> bool:
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert.not_valid_after_utc - datetime.now(UTC) < timedelta(days=within_days)
