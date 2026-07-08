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
    with_case(
        subcommands.add_parser("token-encrypt"),
        handle_token_encrypt,
    )
    with_hex(
        subcommands.add_parser("token-decrypt"),
        handle_token_decrypt,
    )
    with_case(
        subcommands.add_parser("identity-encrypt"),
        handle_identity_encrypt,
    )
    with_hex(
        subcommands.add_parser("identity-decrypt"),
        handle_identity_decrypt,
    )
    with_case(
        subcommands.add_parser("ifac-apply"),
        handle_ifac_apply,
    )
    with_hex(
        subcommands.add_parser("ifac-verify"),
        handle_ifac_verify,
    )
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


def handle_probe(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    del store
    reticulum_path = args.reticulum_path or os.environ.get("HYF_RETICULUM_PATH")
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

    sys.path.insert(0, str(path))
    try:
        import RNS  # type: ignore[import-not-found]
    except ImportError as error:
        raise OracleError("invalid_environment: RNS import failed") from error

    return envelope(
        "probe",
        {
            "cryptography": package_version("cryptography"),
            "module": str(Path(RNS.__file__)),
            "pyserial": package_version("pyserial"),
            "rns_version": getattr(RNS, "__version__", None),
            "status": "passed",
        },
        mode="python_reticulum",
    )


def handle_hkdf_vector(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_2("hkdf_vectors.json"), args.case_id)
    return case_envelope("hkdf-vector", case)


def handle_token_encrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_2("token_vectors.json"), args.case_id)
    return case_envelope("token-encrypt", case)


def handle_token_decrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    token_hex = validate_hex(args.hex_value, "token")
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


def handle_identity_encrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
    case = find_case(store.profile_2("identity_encrypt_vectors.json"), args.case_id)
    return case_envelope("identity-encrypt", case)


def handle_identity_decrypt(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
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
    case = find_case(store.profile_2("ifac_vectors.json"), args.case_id)
    return case_envelope("ifac-apply", case)


def handle_ifac_verify(args: argparse.Namespace, store: FixtureStore) -> dict[str, Any]:
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


def package_version(package_name: str) -> str | None:
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
