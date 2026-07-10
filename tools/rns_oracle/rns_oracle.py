#!/usr/bin/env python3
"""HYF RNS fixture oracle command surface."""

from __future__ import annotations

import argparse
import hashlib
import hmac as std_hmac
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


RETICULUM_REPO = "https://github.com/markqvist/Reticulum"
RETICULUM_COMMIT = "422dc05549bf28f45e9b9c5172336a1ba4df0ec0"
PROFILE_1 = "profile_1_kiss_rnode"
PROFILE_2 = "profile_2_crypto_ifac"
REQUIRED_PACKAGES = {
    "cryptography": "49.0.0",
    "pyserial": "3.5",
}

FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class OracleError(Exception):
    """Expected command failure with a diagnostic-safe message."""


class FixtureStore:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def profile_1(self, filename: str) -> dict[str, Any]:
        return self._load("fixtures/rns/profile_1_kiss_rnode", filename)

    def profile_2(self, filename: str) -> dict[str, Any]:
        return self._load("fixtures/rns/profile_2_crypto_ifac", filename)

    def _load(self, directory: str, filename: str) -> dict[str, Any]:
        path = self.repo_root / directory / filename
        try:
            with path.open("r", encoding="utf-8") as fixture:
                value = json.load(fixture)
        except FileNotFoundError as error:
            raise OracleError(f"fixture file not found: {path}") from error
        except json.JSONDecodeError as error:
            raise OracleError(f"fixture file is not valid JSON: {path}") from error
        if not isinstance(value, dict):
            raise OracleError(f"fixture file is not a JSON object: {path}")
        return value


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = FixtureStore(repo_root())

    try:
        result = args.handler(args, store)
    except OracleError as error:
        print(str(error), file=sys.stderr)
        return 2

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rns_oracle")
    subcommands = parser.add_subparsers(dest="command", required=True)

    probe = subcommands.add_parser("probe")
    probe.add_argument("--reticulum-path")
    probe.set_defaults(handler=handle_probe)

    with_case(
        subcommands.add_parser("hkdf-vector"),
        handle_hkdf_vector,
    )
    token_encrypt = subcommands.add_parser("token-encrypt")
    with_case(token_encrypt, handle_token_encrypt)
    add_token_test_flags(token_encrypt)

    token_decrypt = subcommands.add_parser("token-decrypt")
    with_hex(token_decrypt, handle_token_decrypt)
    add_token_test_flags(token_decrypt)

    identity_encrypt = subcommands.add_parser("identity-encrypt")
    with_case(identity_encrypt, handle_identity_encrypt)
    add_identity_encrypt_test_flags(identity_encrypt)

    identity_decrypt = subcommands.add_parser("identity-decrypt")
    with_hex(identity_decrypt, handle_identity_decrypt)
    add_identity_test_flags(identity_decrypt)

    ifac_apply = subcommands.add_parser("ifac-apply")
    with_case(ifac_apply, handle_ifac_apply)
    add_ifac_test_flags(ifac_apply)

    ifac_verify = subcommands.add_parser("ifac-verify")
    with_hex(ifac_verify, handle_ifac_verify)
    add_ifac_test_flags(ifac_verify)

    with_case(
        subcommands.add_parser("kiss-encode"),
        handle_kiss_encode,
    )
    with_hex(
        subcommands.add_parser("kiss-decode"),
        handle_kiss_decode,
    )
    with_case(
        subcommands.add_parser("rnode-command"),
        handle_rnode_command,
    )

    return parser


def with_case(parser: argparse.ArgumentParser, handler: Any) -> None:
    parser.add_argument("--case", required=True, dest="case_id")
    parser.set_defaults(handler=handler)


def with_hex(parser: argparse.ArgumentParser, handler: Any) -> None:
    parser.add_argument("--hex", required=True, dest="hex_value")
    parser.set_defaults(handler=handler)


def add_token_test_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reticulum-path")
    parser.add_argument("--test-token-key-hex")
    parser.add_argument("--test-plaintext-hex")
    parser.add_argument("--test-iv-hex")


def add_identity_test_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reticulum-path")
    parser.add_argument("--test-recipient-secret-identity-hex")


def add_identity_encrypt_test_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reticulum-path")
    parser.add_argument("--test-recipient-public-identity-hex")
    parser.add_argument("--test-recipient-secret-identity-hex")
    parser.add_argument("--test-plaintext-hex")
    parser.add_argument("--test-ephemeral-secret-hex")
    parser.add_argument("--test-iv-hex")


def add_ifac_test_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reticulum-path")
    parser.add_argument("--test-ifac-identity-secret-hex")
    parser.add_argument("--test-ifac-key-hex")
    parser.add_argument("--test-ifac-size", type=int)


def handle_probe(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    del store
    rns, packages, module_path = load_reticulum(args)

    return envelope(
        "probe",
        {
            "cryptography": packages["cryptography"],
            "module": str(module_path),
            "pyserial": packages["pyserial"],
            "rns_version": getattr(rns, "__version__", None),
            "status": "passed",
        },
        mode="python_reticulum",
    )


def load_reticulum(args: argparse.Namespace) -> tuple[Any, dict[str, str], Path]:
    reticulum_path = getattr(args, "reticulum_path", None) or os.environ.get("HYF_RETICULUM_PATH")
    if not reticulum_path:
        raise OracleError("invalid_environment: missing Reticulum path")

    path = Path(reticulum_path)
    if not path.is_dir():
        raise OracleError("invalid_environment: Reticulum path is not a directory")

    commit = git_stdout(path, "rev-parse", "HEAD")
    if commit != RETICULUM_COMMIT:
        raise OracleError("invalid_environment: Reticulum commit mismatch")

    status = git_stdout(path, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise OracleError("invalid_environment: Reticulum worktree is dirty")

    packages = required_package_versions()

    sys.path.insert(0, str(path))
    try:
        import RNS  # type: ignore[import-not-found]
    except ImportError as error:
        raise OracleError("invalid_environment: RNS import failed") from error

    module_path = Path(RNS.__file__).resolve()
    try:
        module_path.relative_to(path.resolve())
    except ValueError as error:
        raise OracleError("invalid_environment: RNS import resolved outside Reticulum path") from error

    return RNS, packages, module_path


def handle_hkdf_vector(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_2("hkdf_vectors.json"), args.case_id)
    return case_envelope("hkdf-vector", case)


def handle_token_encrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    if has_token_generation_test_inputs(args):
        token_key_hex, plaintext_hex, iv_hex = validate_token_generation_test_inputs(args)
        return handle_token_encrypt_test_only(
            args,
            token_key_hex,
            plaintext_hex,
            iv_hex,
        )
    case = find_case(store.profile_2("token_vectors.json"), args.case_id)
    return case_envelope("token-encrypt", case)


def handle_token_decrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    token_key_hex = validate_token_test_inputs(args)
    token_hex = validate_hex(args.hex_value, "token")
    if token_key_hex is not None:
        return handle_token_decrypt_with_reticulum(args, token_hex, token_key_hex)
    for case in store.profile_2("token_vectors.json")["cases"]:
        if case.get("expected", {}).get("token_hex") == token_hex:
            return envelope(
                "token-decrypt",
                {
                    "case_id": case["case_id"],
                    "valid": True,
                    "plaintext_hex": case["inputs"]["plaintext_hex"],
                },
            )
    for case in store.profile_2("token_negative_vectors.json")["cases"]:
        if case.get("inputs", {}).get("token_hex") == token_hex:
            return envelope(
                "token-decrypt",
                {
                    "case_id": case["case_id"],
                    "valid": False,
                    "error": case["expected"].get("error"),
                },
            )
    raise OracleError("unknown token hex")


def handle_token_decrypt_with_reticulum(
    args: argparse.Namespace,
    token_hex: str,
    token_key_hex: str,
) -> dict[str, Any]:
    try:
        plaintext = decrypt_token_with_reticulum(args, token_hex, token_key_hex)
    except OracleError:
        raise
    except Exception as error:
        return envelope(
            "token-decrypt",
            {
                "valid": False,
                "token_hex": token_hex,
                "error": classify_token_decrypt_error(error),
            },
            mode="python_reticulum",
        )

    return envelope(
        "token-decrypt",
        {
            "valid": True,
            "token_hex": token_hex,
            "plaintext_hex": plaintext.hex(),
        },
        mode="python_reticulum",
    )


def handle_identity_encrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    if has_identity_encrypt_test_inputs(args):
        (
            recipient_public_hex,
            recipient_secret_hex,
            plaintext_hex,
            ephemeral_secret_hex,
            iv_hex,
        ) = validate_identity_encrypt_test_inputs(args)
        return handle_identity_encrypt_test_only(
            args,
            recipient_public_hex,
            recipient_secret_hex,
            plaintext_hex,
            ephemeral_secret_hex,
            iv_hex,
        )
    case = find_case(store.profile_2("identity_encrypt_vectors.json"), args.case_id)
    return case_envelope("identity-encrypt", case)


def handle_identity_decrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    recipient_secret_hex = validate_identity_test_inputs(args)
    ciphertext_hex = validate_hex(args.hex_value, "ciphertext")
    if recipient_secret_hex is not None:
        return handle_identity_decrypt_with_reticulum(args, ciphertext_hex, recipient_secret_hex)
    for case in store.profile_2("identity_decrypt_vectors.json")["cases"]:
        if case.get("inputs", {}).get("ciphertext_token_hex") == ciphertext_hex:
            expected = case["expected"]
            result = {
                "case_id": case["case_id"],
                "valid": expected["valid"],
            }
            if expected.get("plaintext_hex") is not None:
                result["plaintext_hex"] = expected["plaintext_hex"]
            if expected.get("error") is not None:
                result["error"] = expected["error"]
            return envelope("identity-decrypt", result)
    raise OracleError("unknown identity ciphertext hex")


def handle_identity_decrypt_with_reticulum(
    args: argparse.Namespace,
    ciphertext_hex: str,
    recipient_secret_hex: str,
) -> dict[str, Any]:
    plaintext = decrypt_identity_with_reticulum(args, ciphertext_hex, recipient_secret_hex)
    if plaintext is None:
        return envelope(
            "identity-decrypt",
            {
                "valid": False,
                "ciphertext_token_hex": ciphertext_hex,
                "error": "decrypt_failed",
            },
            mode="python_reticulum",
        )

    return envelope(
        "identity-decrypt",
        {
            "valid": True,
            "ciphertext_token_hex": ciphertext_hex,
            "plaintext_hex": plaintext.hex(),
        },
        mode="python_reticulum",
    )


def handle_ifac_apply(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    if has_ifac_test_inputs(args):
        ifac_identity_secret_hex, ifac_key_hex, ifac_size = validate_ifac_test_inputs(args)
        case = find_case(store.profile_2("ifac_vectors.json"), args.case_id)
        raw_packet_hex = validate_hex(case["raw_packet_hex"], "raw packet")
        masked_packet = apply_ifac_with_reticulum(
            args,
            raw_packet_hex,
            ifac_identity_secret_hex,
            ifac_key_hex,
            ifac_size,
        )
        return envelope(
            "ifac-apply",
            {
                "case_id": args.case_id,
                "masked_hex": masked_packet.hex(),
                "valid": True,
            },
            mode="python_reticulum",
        )
    case = find_case(store.profile_2("ifac_vectors.json"), args.case_id)
    return case_envelope("ifac-apply", case)


def handle_ifac_verify(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    if has_ifac_test_inputs(args):
        ifac_identity_secret_hex, ifac_key_hex, ifac_size = validate_ifac_test_inputs(args)
        masked_packet_hex = validate_hex(args.hex_value, "masked packet")
        return verify_ifac_with_reticulum(
            args,
            masked_packet_hex,
            ifac_identity_secret_hex,
            ifac_key_hex,
            ifac_size,
        )
    masked_packet_hex = validate_hex(args.hex_value, "masked packet")
    for case in store.profile_2("ifac_vectors.json")["cases"]:
        if case.get("masked_packet_hex") == masked_packet_hex:
            return envelope(
                "ifac-verify",
                {
                    "case_id": case["case_id"],
                    "valid": True,
                    "masked_hex": masked_packet_hex,
                    "unmasked_hex": case["expected_unmasked_hex"],
                },
            )
    for case in store.profile_2("ifac_negative_vectors.json")["cases"]:
        if case.get("masked_packet_hex") == masked_packet_hex:
            return envelope(
                "ifac-verify",
                {
                    "case_id": case["case_id"],
                    "valid": False,
                    "masked_hex": masked_packet_hex,
                    "error": case["expected_error"],
                },
            )
    raise OracleError("unknown IFAC packet hex")


def apply_ifac_with_reticulum(
    args: argparse.Namespace,
    raw_packet_hex: str,
    ifac_identity_secret_hex: str,
    ifac_key_hex: str,
    ifac_size: int,
) -> bytes:
    rns, _packages, _module_path = load_reticulum(args)

    class CaptureInterface:
        def __init__(self) -> None:
            self.outgoing: bytes | None = None

        def process_outgoing(self, data: bytes) -> None:
            self.outgoing = data

        def __str__(self) -> str:
            return "hyf-ifac-oracle"

    CaptureInterface.ifac_identity = rns.Identity.from_bytes(
        bytes.fromhex(ifac_identity_secret_hex)
    )
    CaptureInterface.ifac_key = bytes.fromhex(ifac_key_hex)
    CaptureInterface.ifac_size = ifac_size

    interface = CaptureInterface()
    rns.Transport.transmit(interface, bytes.fromhex(raw_packet_hex))
    if interface.outgoing is None:
        raise OracleError("Reticulum IFAC apply did not emit a packet")
    return interface.outgoing


def verify_ifac_with_reticulum(
    args: argparse.Namespace,
    masked_packet_hex: str,
    ifac_identity_secret_hex: str,
    ifac_key_hex: str,
    ifac_size: int,
) -> dict[str, Any]:
    rns, _packages, _module_path = load_reticulum(args)
    if len(masked_packet_hex) // 2 <= 2 + ifac_size:
        return envelope(
            "ifac-verify",
            {
                "valid": False,
                "masked_hex": masked_packet_hex,
                "error": "packet_too_short",
            },
            mode="python_reticulum",
        )
    if bytes.fromhex(masked_packet_hex)[0] & 0x80 != 0x80:
        return envelope(
            "ifac-verify",
            {
                "valid": False,
                "masked_hex": masked_packet_hex,
                "error": "missing_packet_access_code",
            },
            mode="python_reticulum",
        )

    captured: dict[str, bytes] = {}

    class CaptureInterface:
        pass

    CaptureInterface.ifac_identity = rns.Identity.from_bytes(
        bytes.fromhex(ifac_identity_secret_hex)
    )
    CaptureInterface.ifac_key = bytes.fromhex(ifac_key_hex)
    CaptureInterface.ifac_size = ifac_size

    class CapturePacket:
        def __init__(self, destination: Any, raw: bytes) -> None:
            del destination
            captured["raw"] = raw

        def unpack(self) -> bool:
            return False

    original_packet = rns.Packet
    original_ready = rns.Transport.ready
    original_identity = rns.Transport.identity
    try:
        rns.Packet = CapturePacket
        rns.Transport.ready = True
        rns.Transport.identity = object()
        rns.Transport.inbound(bytes.fromhex(masked_packet_hex), CaptureInterface())
    finally:
        rns.Packet = original_packet
        rns.Transport.ready = original_ready
        rns.Transport.identity = original_identity

    unmasked_packet = captured.get("raw")
    if unmasked_packet is None:
        return envelope(
            "ifac-verify",
            {
                "valid": False,
                "masked_hex": masked_packet_hex,
                "error": "invalid_packet_access_code",
            },
            mode="python_reticulum",
        )

    return envelope(
        "ifac-verify",
        {
            "valid": True,
            "masked_hex": masked_packet_hex,
            "unmasked_hex": unmasked_packet.hex(),
        },
        mode="python_reticulum",
    )


def handle_token_encrypt_test_only(
    args: argparse.Namespace,
    token_key_hex: str,
    plaintext_hex: str,
    iv_hex: str,
) -> dict[str, Any]:
    plaintext = bytes.fromhex(plaintext_hex)
    token = token_encrypt_with_iv_for_oracle(
        bytes.fromhex(token_key_hex),
        plaintext,
        bytes.fromhex(iv_hex),
    )
    validated_plaintext = decrypt_token_with_reticulum(args, token.hex(), token_key_hex)
    if validated_plaintext != plaintext:
        raise OracleError("token generation Reticulum self-validation mismatch")
    return envelope(
        "token-encrypt",
        {
            "case_id": args.case_id,
            "valid": True,
            "plaintext_hex": plaintext.hex(),
            "reticulum_self_validation": "passed",
            "test_only_secret_material": True,
            "token_hex": token.hex(),
        },
        mode="test_only_oracle_shim",
    )


def handle_identity_encrypt_test_only(
    args: argparse.Namespace,
    recipient_public_hex: str,
    recipient_secret_hex: str,
    plaintext_hex: str,
    ephemeral_secret_hex: str,
    iv_hex: str,
) -> dict[str, Any]:
    recipient_public = bytes.fromhex(recipient_public_hex)
    plaintext = bytes.fromhex(plaintext_hex)
    ephemeral_public, token_key = derive_identity_token_key_for_oracle(
        recipient_public,
        bytes.fromhex(ephemeral_secret_hex),
    )
    token = token_encrypt_with_iv_for_oracle(
        token_key,
        plaintext,
        bytes.fromhex(iv_hex),
    )
    ciphertext_token = ephemeral_public + token
    validated_plaintext = decrypt_identity_with_reticulum(
        args,
        ciphertext_token.hex(),
        recipient_secret_hex,
    )
    if validated_plaintext != plaintext:
        raise OracleError("identity generation Reticulum self-validation mismatch")
    return envelope(
        "identity-encrypt",
        {
            "case_id": args.case_id,
            "ciphertext_token_hex": ciphertext_token.hex(),
            "ephemeral_public_hex": ephemeral_public.hex(),
            "plaintext_hex": plaintext.hex(),
            "reticulum_self_validation": "passed",
            "test_only_secret_material": True,
            "valid": True,
        },
        mode="test_only_oracle_shim",
    )


def handle_kiss_encode(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_1("kiss_vectors.json"), args.case_id)
    command = int(validate_hex(case["command_hex"], "command"), 16)
    payload = bytes.fromhex(validate_hex(case["payload_hex"], "payload", allow_empty=True))
    encoded = encode_kiss(command, payload).hex()
    if encoded != case["encoded_hex"]:
        raise OracleError("KISS fixture replay mismatch")
    return case_envelope("kiss-encode", case)


def handle_kiss_decode(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    del store
    frame_hex = validate_hex(args.hex_value, "KISS frame")
    frame = bytes.fromhex(frame_hex)
    frames = decode_kiss(frame)
    return envelope(
        "kiss-decode",
        {
            "encoded_hex": frame_hex,
            "frames": [
                {
                    "kind": "data" if command == 0 else "command",
                    "command_hex": f"{command:02x}",
                    "payload_hex": payload.hex(),
                }
                for command, payload in frames
            ],
        },
    )


def handle_rnode_command(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_1("rnode_command_vectors.json"), args.case_id)
    command = int(validate_hex(case["command_byte_hex"], "command"), 16)
    payload = bytes.fromhex(validate_hex(case["payload_hex"], "payload"))
    encoded = encode_kiss(command, payload).hex()
    if encoded != case["kiss_frame_hex"]:
        raise OracleError("RNode fixture replay mismatch")
    return case_envelope("rnode-command", case)


def token_encrypt_with_iv_for_oracle(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    signing_key, encryption_key = split_token_key_for_oracle(key)
    padded = pkcs7_pad_for_oracle(plaintext)
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    authenticated = iv + ciphertext
    tag = std_hmac.new(signing_key, authenticated, hashlib.sha256).digest()
    return authenticated + tag


def decrypt_token_with_reticulum(
    args: argparse.Namespace,
    token_hex: str,
    token_key_hex: str,
) -> bytes:
    load_reticulum(args)
    try:
        from RNS.Cryptography.Token import Token  # type: ignore[import-not-found]
    except ImportError as error:
        raise OracleError("invalid_environment: RNS Token import failed") from error

    return Token(bytes.fromhex(token_key_hex)).decrypt(bytes.fromhex(token_hex))


def decrypt_identity_with_reticulum(
    args: argparse.Namespace,
    ciphertext_hex: str,
    recipient_secret_hex: str,
) -> bytes | None:
    rns, _packages, _module_path = load_reticulum(args)
    identity = rns.Identity.from_bytes(bytes.fromhex(recipient_secret_hex))
    return identity.decrypt(bytes.fromhex(ciphertext_hex))


def split_token_key_for_oracle(key: bytes) -> tuple[bytes, bytes]:
    if len(key) == 32:
        return key[:16], key[16:]
    if len(key) == 64:
        return key[:32], key[32:]
    raise OracleError("test token key hex must be 32 or 64 bytes")


def pkcs7_pad_for_oracle(plaintext: bytes) -> bytes:
    block_len = 16
    padding_len = block_len - (len(plaintext) % block_len)
    return plaintext + bytes([padding_len]) * padding_len


def derive_identity_token_key_for_oracle(
    recipient_public_identity: bytes,
    ephemeral_secret: bytes,
) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    recipient_x25519_public = recipient_public_identity[:32]
    ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(ephemeral_secret)
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_key = ephemeral_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_x25519_public)
    )
    if not any(shared_key):
        raise OracleError("invalid test recipient public identity")

    salt = hashlib.sha256(recipient_public_identity).digest()[:16]
    token_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=None,
    ).derive(shared_key)
    return ephemeral_public, token_key


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_case(fixture: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        raise OracleError("fixture does not contain a cases array")
    for case in cases:
        if isinstance(case, dict) and case.get("case_id") == case_id:
            return case
    raise OracleError(f"unknown case: {case_id}")


def case_envelope(command: str, case: dict[str, Any]) -> dict[str, Any]:
    return envelope(command, {"case": case})


def envelope(
    command: str,
    payload: dict[str, Any],
    *,
    mode: str = "fixture_replay",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "command": command,
        "oracle": {
            "mode": mode,
            "package": "tools/rns_oracle",
            "python": sys.version.split()[0],
            "reticulum": {
                "repo": RETICULUM_REPO,
                "commit": RETICULUM_COMMIT,
            },
        },
    }
    result.update(payload)
    return result


def validate_hex(value: str, label: str, *, allow_empty: bool = False) -> str:
    if value == "":
        if allow_empty:
            return ""
        raise OracleError(f"{label} hex must not be empty")
    if len(value) % 2 != 0:
        raise OracleError(f"{label} hex must have an even length")
    if any(character not in HEX_DIGITS for character in value):
        raise OracleError(f"{label} is not valid canonical hex")
    return value.lower()


def validate_optional_hex(
    args: argparse.Namespace,
    attr: str,
    label: str,
    *,
    lengths: set[int] | None = None,
    allow_empty: bool = False,
) -> str | None:
    value = getattr(args, attr, None)
    if value is None:
        return None
    normalized = validate_hex(value, label, allow_empty=allow_empty)
    byte_len = len(normalized) // 2
    if lengths is not None and byte_len not in lengths:
        allowed = " or ".join(str(length) for length in sorted(lengths))
        raise OracleError(f"{label} hex must be {allowed} bytes")
    return normalized


def validate_token_test_inputs(args: argparse.Namespace) -> str | None:
    token_key_hex = validate_optional_hex(
        args,
        "test_token_key_hex",
        "test token key",
        lengths={32, 64},
    )
    validate_optional_hex(args, "test_plaintext_hex", "test plaintext", allow_empty=True)
    validate_optional_hex(args, "test_iv_hex", "test IV", lengths={16})
    return token_key_hex


def validate_token_generation_test_inputs(args: argparse.Namespace) -> tuple[str, str, str]:
    token_key_hex = validate_token_test_inputs(args)
    plaintext_hex = validate_optional_hex(
        args,
        "test_plaintext_hex",
        "test plaintext",
        allow_empty=True,
    )
    iv_hex = validate_optional_hex(args, "test_iv_hex", "test IV", lengths={16})
    if token_key_hex is None or plaintext_hex is None or iv_hex is None:
        raise OracleError(
            "token generation test inputs require token key, plaintext, and IV"
        )
    return token_key_hex, plaintext_hex, iv_hex


def validate_identity_test_inputs(args: argparse.Namespace) -> str | None:
    return validate_optional_hex(
        args,
        "test_recipient_secret_identity_hex",
        "test recipient secret identity",
        lengths={64},
    )


def validate_identity_encrypt_test_inputs(
    args: argparse.Namespace,
) -> tuple[str, str, str, str, str]:
    recipient_public_hex = validate_optional_hex(
        args,
        "test_recipient_public_identity_hex",
        "test recipient public identity",
        lengths={64},
    )
    recipient_secret_hex = validate_optional_hex(
        args,
        "test_recipient_secret_identity_hex",
        "test recipient secret identity",
        lengths={64},
    )
    plaintext_hex = validate_optional_hex(
        args,
        "test_plaintext_hex",
        "test plaintext",
        allow_empty=True,
    )
    ephemeral_secret_hex = validate_optional_hex(
        args,
        "test_ephemeral_secret_hex",
        "test ephemeral secret",
        lengths={32},
    )
    iv_hex = validate_optional_hex(args, "test_iv_hex", "test IV", lengths={16})
    if (
        recipient_public_hex is None
        or recipient_secret_hex is None
        or plaintext_hex is None
        or ephemeral_secret_hex is None
        or iv_hex is None
    ):
        raise OracleError(
            "identity generation test inputs require recipient public identity, "
            "recipient secret identity, plaintext, ephemeral secret, and IV"
        )
    return (
        recipient_public_hex,
        recipient_secret_hex,
        plaintext_hex,
        ephemeral_secret_hex,
        iv_hex,
    )


def validate_ifac_test_inputs(args: argparse.Namespace) -> tuple[str, str, int]:
    ifac_size = getattr(args, "test_ifac_size", None)
    if ifac_size is not None and not 1 <= ifac_size <= 64:
        raise OracleError("test IFAC size must be between 1 and 64 bytes")
    ifac_identity_secret_hex = validate_optional_hex(
        args,
        "test_ifac_identity_secret_hex",
        "test IFAC identity secret",
        lengths={64},
    )
    ifac_key_hex = validate_optional_hex(args, "test_ifac_key_hex", "test IFAC key")
    if ifac_identity_secret_hex is None or ifac_key_hex is None or ifac_size is None:
        raise OracleError(
            "IFAC test inputs require IFAC identity secret, IFAC key, and IFAC size"
        )
    return ifac_identity_secret_hex, ifac_key_hex, ifac_size


def has_ifac_test_inputs(args: argparse.Namespace) -> bool:
    return (
        getattr(args, "test_ifac_identity_secret_hex", None) is not None
        or getattr(args, "test_ifac_key_hex", None) is not None
        or getattr(args, "test_ifac_size", None) is not None
    )


def has_token_generation_test_inputs(args: argparse.Namespace) -> bool:
    return (
        getattr(args, "test_token_key_hex", None) is not None
        or getattr(args, "test_plaintext_hex", None) is not None
        or getattr(args, "test_iv_hex", None) is not None
    )


def has_identity_encrypt_test_inputs(args: argparse.Namespace) -> bool:
    return (
        getattr(args, "test_recipient_public_identity_hex", None) is not None
        or getattr(args, "test_recipient_secret_identity_hex", None) is not None
        or getattr(args, "test_plaintext_hex", None) is not None
        or getattr(args, "test_ephemeral_secret_hex", None) is not None
        or getattr(args, "test_iv_hex", None) is not None
    )


def classify_token_decrypt_error(error: Exception) -> str:
    message = str(error).lower()
    if "hmac was invalid" in message:
        return "authentication_failed"
    if "cannot verify hmac" in message:
        return "invalid_token"
    if "padding" in message or "unpad" in message:
        return "invalid_padding"
    return "invalid_token"


def encode_kiss(command: int, payload: bytes) -> bytes:
    output = bytearray([FEND, command])
    for byte in payload:
        if byte == FEND:
            output.extend([FESC, TFEND])
        elif byte == FESC:
            output.extend([FESC, TFESC])
        else:
            output.append(byte)
    output.append(FEND)
    return bytes(output)


def decode_kiss(frame: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    buffer = bytearray()
    in_frame = False
    escape = False
    for byte in frame:
        if byte == FEND:
            if in_frame and buffer:
                command = buffer[0]
                frames.append((command, bytes(buffer[1:])))
            buffer.clear()
            in_frame = True
            escape = False
            continue
        if not in_frame:
            continue
        if escape:
            if byte == TFEND:
                buffer.append(FEND)
            elif byte == TFESC:
                buffer.append(FESC)
            else:
                raise OracleError("malformed KISS escape")
            escape = False
            continue
        if byte == FESC:
            escape = True
            continue
        buffer.append(byte)
    if escape:
        raise OracleError("unterminated KISS escape")
    if in_frame and buffer:
        raise OracleError("unterminated KISS frame")
    if not frames:
        raise OracleError("no KISS frame decoded")
    return frames


def git_stdout(repo: Path, *args: str) -> str:
    try:
        output = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise OracleError("invalid_environment: git command unavailable") from error
    if output.returncode != 0:
        raise OracleError("invalid_environment: git command failed")
    return output.stdout.strip()


def required_package_versions() -> dict[str, str]:
    versions = {}
    for package_name, required_version in REQUIRED_PACKAGES.items():
        actual_version = package_version(package_name)
        if actual_version != required_version:
            actual = actual_version if actual_version is not None else "missing"
            raise OracleError(
                f"invalid_environment: {package_name} version mismatch: "
                f"expected {required_version}, actual {actual}"
            )
        versions[package_name] = actual_version
    return versions


def package_version(package_name: str) -> str | None:
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
