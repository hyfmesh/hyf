#!/usr/bin/env python3
"""HYF RNS fixture oracle command surface."""

from __future__ import annotations

import argparse
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

    with_case(
        subcommands.add_parser("identity-encrypt"),
        handle_identity_encrypt,
    )

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
    parser.add_argument("--test-recipient-secret-identity-hex")
    parser.add_argument("--test-ratchet-secret-hex", action="append", default=[])


def add_ifac_test_flags(parser: argparse.ArgumentParser) -> None:
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
    validate_token_test_inputs(args)
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
    load_reticulum(args)
    from RNS.Cryptography.Token import Token  # type: ignore[import-not-found]

    try:
        plaintext = Token(bytes.fromhex(token_key_hex)).decrypt(bytes.fromhex(token_hex))
    except Exception as error:
        return envelope(
            "token-decrypt",
            {
                "valid": False,
                "error": classify_token_decrypt_error(error),
            },
            mode="python_reticulum",
        )

    return envelope(
        "token-decrypt",
        {
            "valid": True,
            "plaintext_hex": plaintext.hex(),
        },
        mode="python_reticulum",
    )


def handle_identity_encrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_2("identity_encrypt_vectors.json"), args.case_id)
    return case_envelope("identity-encrypt", case)


def handle_identity_decrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    validate_identity_test_inputs(args)
    ciphertext_hex = validate_hex(args.hex_value, "ciphertext")
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


def handle_ifac_apply(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    validate_ifac_test_inputs(args)
    case = find_case(store.profile_2("ifac_vectors.json"), args.case_id)
    return case_envelope("ifac-apply", case)


def handle_ifac_verify(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    validate_ifac_test_inputs(args)
    masked_packet_hex = validate_hex(args.hex_value, "masked packet")
    for case in store.profile_2("ifac_vectors.json")["cases"]:
        if case.get("masked_packet_hex") == masked_packet_hex:
            return envelope(
                "ifac-verify",
                {
                    "case_id": case["case_id"],
                    "valid": True,
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
                    "error": case["expected_error"],
                },
            )
    raise OracleError("unknown IFAC packet hex")


def handle_kiss_encode(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_1("kiss_vectors.json"), args.case_id)
    command = int(validate_hex(case["command_hex"], "command"), 16)
    payload = bytes.fromhex(validate_hex(case["payload_hex"], "payload"))
    encoded = encode_kiss(command, payload).hex()
    if encoded != case["encoded_hex"]:
        raise OracleError("KISS fixture replay mismatch")
    return case_envelope("kiss-encode", case)


def handle_kiss_decode(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    del store
    frame = bytes.fromhex(validate_hex(args.hex_value, "KISS frame"))
    frames = decode_kiss(frame)
    return envelope(
        "kiss-decode",
        {
            "encoded_hex": args.hex_value.lower(),
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


def validate_hex(value: str, label: str) -> str:
    normalized = value.lower()
    if len(normalized) % 2 != 0:
        raise OracleError(f"{label} hex must have an even length")
    try:
        bytes.fromhex(normalized)
    except ValueError as error:
        raise OracleError(f"{label} is not valid hex") from error
    return normalized


def validate_optional_hex(
    args: argparse.Namespace,
    attr: str,
    label: str,
    *,
    lengths: set[int] | None = None,
) -> str | None:
    value = getattr(args, attr, None)
    if value is None:
        return None
    normalized = validate_hex(value, label)
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
    validate_optional_hex(args, "test_plaintext_hex", "test plaintext")
    validate_optional_hex(args, "test_iv_hex", "test IV", lengths={16})
    return token_key_hex


def validate_identity_test_inputs(args: argparse.Namespace) -> None:
    validate_optional_hex(
        args,
        "test_recipient_secret_identity_hex",
        "test recipient secret identity",
        lengths={64},
    )
    for ratchet_hex in getattr(args, "test_ratchet_secret_hex", []):
        normalized = validate_hex(ratchet_hex, "test ratchet secret")
        if len(normalized) // 2 != 32:
            raise OracleError("test ratchet secret hex must be 32 bytes")


def validate_ifac_test_inputs(args: argparse.Namespace) -> None:
    validate_optional_hex(
        args,
        "test_ifac_identity_secret_hex",
        "test IFAC identity secret",
        lengths={64},
    )
    validate_optional_hex(args, "test_ifac_key_hex", "test IFAC key")
    if getattr(args, "test_ifac_size", None) is not None:
        if not 1 <= args.test_ifac_size <= 64:
            raise OracleError("test IFAC size must be between 1 and 64 bytes")


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
