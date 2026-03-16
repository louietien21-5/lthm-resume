import copy
import base64
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from webauthn.helpers.structs import AuthenticatorTransport, CredentialDeviceType, PublicKeyCredentialDescriptor


def bytes_to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_to_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


class PasskeyStoreError(RuntimeError):
    pass


@dataclass
class StoredCredential:
    credential_id: str
    public_key: str
    sign_count: int
    transports: list[str]
    device_type: str
    backed_up: bool
    label: str
    created_at: str
    last_used_at: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "StoredCredential":
        required_string_fields = (
            "credential_id",
            "public_key",
            "device_type",
            "label",
            "created_at",
            "last_used_at",
        )
        for field in required_string_fields:
            if not isinstance(payload.get(field), str):
                raise PasskeyStoreError(f"Passkey store credential field {field} is invalid.")

        sign_count = payload.get("sign_count")
        transports = payload.get("transports")
        backed_up = payload.get("backed_up")
        if not isinstance(sign_count, int):
            raise PasskeyStoreError("Passkey store credential sign_count is invalid.")
        if not isinstance(transports, list) or not all(isinstance(item, str) for item in transports):
            raise PasskeyStoreError("Passkey store credential transports are invalid.")
        if not isinstance(backed_up, bool):
            raise PasskeyStoreError("Passkey store credential backed_up is invalid.")

        return cls(
            credential_id=payload["credential_id"],
            public_key=payload["public_key"],
            sign_count=sign_count,
            transports=transports,
            device_type=payload["device_type"],
            backed_up=backed_up,
            label=payload["label"],
            created_at=payload["created_at"],
            last_used_at=payload["last_used_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "public_key": self.public_key,
            "sign_count": self.sign_count,
            "transports": list(self.transports),
            "device_type": self.device_type,
            "backed_up": self.backed_up,
            "label": self.label,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
        }

    def descriptor(self) -> PublicKeyCredentialDescriptor:
        transports: list[AuthenticatorTransport] = []
        for transport in self.transports:
            try:
                transports.append(AuthenticatorTransport(transport))
            except ValueError as exc:
                raise PasskeyStoreError("Passkey store credential transport is invalid.") from exc

        return PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(self.credential_id),
            transports=transports or None,
        )


class PasskeyStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def _default_store(self) -> dict[str, Any]:
        return {"version": 1, "user_handle_b64url": "", "credentials": []}

    def _load_unlocked(self) -> dict[str, Any]:
        if not self._path.exists():
            return self._default_store()

        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise PasskeyStoreError(f"Could not read passkey store {self._path}.") from exc
        except json.JSONDecodeError as exc:
            raise PasskeyStoreError(f"Passkey store {self._path} is not valid JSON.") from exc

        if not isinstance(payload, dict):
            raise PasskeyStoreError(f"Passkey store {self._path} has an invalid shape.")
        if payload.get("version") != 1:
            raise PasskeyStoreError(f"Passkey store {self._path} has an unsupported version.")
        if not isinstance(payload.get("user_handle_b64url"), str):
            raise PasskeyStoreError(f"Passkey store {self._path} has an invalid user handle.")

        credentials = payload.get("credentials")
        if not isinstance(credentials, list):
            raise PasskeyStoreError(f"Passkey store {self._path} has invalid credentials.")

        normalized_credentials = [StoredCredential.from_dict(item).to_dict() for item in credentials if isinstance(item, dict)]
        if len(normalized_credentials) != len(credentials):
            raise PasskeyStoreError(f"Passkey store {self._path} has an invalid credential entry.")

        return {
            "version": 1,
            "user_handle_b64url": payload["user_handle_b64url"],
            "credentials": normalized_credentials,
        }

    def _write_unlocked(self, payload: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
            temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(temp_path, self._path)
        except OSError as exc:
            raise PasskeyStoreError(f"Could not write passkey store {self._path}.") from exc

    def read(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._load_unlocked())

    def has_credentials(self) -> bool:
        return bool(self.read()["credentials"])

    def credential_count(self) -> int:
        return len(self.read()["credentials"])

    def user_handle_b64url(self) -> str:
        return self.read()["user_handle_b64url"]

    def credentials(self) -> list[StoredCredential]:
        return [StoredCredential.from_dict(item) for item in self.read()["credentials"]]

    def get_credential(self, credential_id: str) -> Optional[StoredCredential]:
        for credential in self.credentials():
            if credential.credential_id == credential_id:
                return credential
        return None

    def add_credential(self, user_handle_b64url: str, credential: StoredCredential) -> None:
        with self._lock:
            payload = self._load_unlocked()
            existing_ids = {item["credential_id"] for item in payload["credentials"]}
            if credential.credential_id in existing_ids:
                raise PasskeyStoreError("Passkey already exists.")
            payload["credentials"].append(credential.to_dict())
            if payload["user_handle_b64url"]:
                if payload["user_handle_b64url"] != user_handle_b64url:
                    raise PasskeyStoreError("Passkey store user handle does not match.")
            else:
                payload["user_handle_b64url"] = user_handle_b64url
            self._write_unlocked(payload)

    def update_credential(self, credential_id: str, **changes: Any) -> StoredCredential:
        with self._lock:
            payload = self._load_unlocked()
            for index, item in enumerate(payload["credentials"]):
                if item["credential_id"] != credential_id:
                    continue
                updated = {**item, **changes}
                stored = StoredCredential.from_dict(updated)
                payload["credentials"][index] = stored.to_dict()
                self._write_unlocked(payload)
                return stored
        raise PasskeyStoreError("Passkey does not exist.")

    def remove_credential(self, credential_id: str) -> None:
        with self._lock:
            payload = self._load_unlocked()
            if len(payload["credentials"]) <= 1:
                raise PasskeyStoreError("Cannot remove the final passkey.")

            remaining = [item for item in payload["credentials"] if item["credential_id"] != credential_id]
            if len(remaining) == len(payload["credentials"]):
                raise PasskeyStoreError("Passkey does not exist.")

            payload["credentials"] = remaining
            self._write_unlocked(payload)


def credential_device_type_value(value: CredentialDeviceType) -> str:
    return value.value
