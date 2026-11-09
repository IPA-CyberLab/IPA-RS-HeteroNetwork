#!/usr/bin/env python3
"""Stream authenticated encryption of etcd snapshots without printing secrets.

The key is a 32-byte owner-only file. Ciphertext is written to stdout only by
the encrypt command. Verification never outputs plaintext. Restore writes a new
owner-only file only after the authentication tag and expected hash validate.
"""
import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAGIC = b"HNN-ETCD-AESGCM-1\n"
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK_BYTES = 1024 * 1024


def read_key(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("key must be an owner-only regular file") from error
    with os.fdopen(descriptor, "rb") as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError("key must be an owner-only regular file")
        data = file.read(33)
    if len(data) != 32:
        raise ValueError("key must contain exactly 32 bytes")
    return data


def generate_key(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(os.urandom(32))
        file.flush()
        os.fsync(file.fileno())


class Throttle:
    def __init__(self, rate):
        self.rate = rate
        self.start = time.monotonic()
        self.total = 0

    def consume(self, size):
        self.total += size
        if self.rate:
            wait = self.total / self.rate - (time.monotonic() - self.start)
            if wait > 0:
                time.sleep(wait)


def encrypt(source, destination, key, rate=0):
    header = MAGIC + os.urandom(NONCE_BYTES)
    encryption = Cipher(algorithms.AES(key), modes.GCM(header[len(MAGIC):])).encryptor()
    encryption.authenticate_additional_data(header)
    destination.write(header)
    digest, throttle = hashlib.sha256(), Throttle(rate)
    for chunk in iter(lambda: source.read(CHUNK_BYTES), b""):
        digest.update(chunk)
        throttle.consume(len(chunk))
        destination.write(encryption.update(chunk))
    destination.write(encryption.finalize())
    destination.write(encryption.tag)
    destination.flush()
    return {"plaintext_sha256": digest.hexdigest(), "plaintext_bytes": throttle.total}


def decrypt(source, destination, key, expected_sha256, rate=0):
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("expected SHA-256 must be lowercase hexadecimal")
    header = source.read(len(MAGIC) + NONCE_BYTES)
    if len(header) != len(MAGIC) + NONCE_BYTES or not header.startswith(MAGIC):
        raise ValueError("snapshot envelope header is invalid")
    decryption = Cipher(algorithms.AES(key), modes.GCM(header[len(MAGIC):])).decryptor()
    decryption.authenticate_additional_data(header)
    tail, digest, throttle = b"", hashlib.sha256(), Throttle(rate)
    for chunk in iter(lambda: source.read(CHUNK_BYTES), b""):
        tail += chunk
        if len(tail) <= TAG_BYTES:
            continue
        encrypted, tail = tail[:-TAG_BYTES], tail[-TAG_BYTES:]
        throttle.consume(len(encrypted))
        plaintext = decryption.update(encrypted)
        digest.update(plaintext)
        if destination is not None:
            destination.write(plaintext)
    if len(tail) != TAG_BYTES:
        raise ValueError("snapshot envelope is truncated")
    final = decryption.finalize_with_tag(tail)
    digest.update(final)
    if destination is not None:
        destination.write(final)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("snapshot plaintext checksum does not match")
    return {"plaintext_sha256": digest.hexdigest(), "plaintext_bytes": throttle.total}


def restore(source, output, key, expected_sha256, rate=0):
    # The final path is never overwritten and unauthenticated bytes remain in
    # a private temporary file until validation succeeds.
    descriptor, temporary = tempfile.mkstemp(prefix=".hnn-etcd-restore-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as file:
            result = decrypt(source, file, key, expected_sha256, rate)
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary, output)
        return result
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("keygen", "encrypt", "verify", "restore"))
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--bytes-per-second", type=int, default=0)
    args = parser.parse_args()
    if args.bytes_per_second < 0:
        raise ValueError("rate limit cannot be negative")
    if args.operation == "keygen":
        generate_key(args.key)
        print(json.dumps({"result": "key_created"}), file=sys.stderr)
        return
    key = read_key(args.key)
    if args.operation == "encrypt":
        if args.input is None:
            raise ValueError("encrypt requires an input file")
        source = nullcontext(sys.stdin.buffer) if str(args.input) == "-" else args.input.open("rb")
        with source as file:
            result = encrypt(file, sys.stdout.buffer, key, args.bytes_per_second)
    elif args.operation == "verify":
        result = decrypt(sys.stdin.buffer, None, key, args.sha256 or "", args.bytes_per_second)
    else:
        if args.output is None:
            raise ValueError("restore requires a new output file")
        result = restore(sys.stdin.buffer, args.output, key, args.sha256 or "", args.bytes_per_second)
    print(json.dumps({"result": "verified" if args.operation != "encrypt" else "encrypted", **result}), file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (InvalidTag, ValueError, OSError) as error:
        sys.exit("Encrypted snapshot operation failed: " + (str(error) or type(error).__name__))
