"""Validation and canonical serialization for sensitive identity data."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
import ipaddress
import json
import re
from typing import Any, Mapping
import uuid as uuidlib

from .exceptions import IdentityValidationError

_MAC_ALIASES = ("mac", "mac_address", "hardware_mac")
_BSSID_ALIASES = ("bssid", "wifi_bssid")
_SERIAL_ALIASES = ("serial", "hardware_serial", "serial_number")
_IP_ALIASES = ("ip", "ip_address")
_UUID_ALIASES = ("uuid",)
_GUID_ALIASES = ("guid",)
_FINGERPRINT_ALIASES = ("browser_fingerprint", "browser_fingerprint_hash")
_GPS_ALIASES = ("gps", "location")


def _first(data: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def _canonical(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _valid_mac(value: Any) -> str:
    if not isinstance(value, str):
        raise IdentityValidationError("MAC/BSSID must be a string")
    compact = re.sub(r"[:.\- ]", "", value.strip())
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
        raise IdentityValidationError("MAC/BSSID is not a 48-bit EUI value")
    groups = [compact[index:index + 2].lower() for index in range(0, 12, 2)]
    return ":".join(groups)


def _valid_ip(value: Any) -> str:
    if not isinstance(value, str):
        raise IdentityValidationError("IP address must be a string")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise IdentityValidationError("invalid IP address") from exc


def _valid_serial(value: Any) -> str:
    if not isinstance(value, str):
        raise IdentityValidationError("hardware serial must be a string")
    value = value.strip()
    if not value or len(value.encode("utf-8")) > 512:
        raise IdentityValidationError("hardware serial must be 1..512 bytes")
    if any(ord(char) < 32 or char == "\x7f" for char in value):
        raise IdentityValidationError("hardware serial contains control characters")
    return value


def _valid_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise IdentityValidationError("UUID/GUID must be a string")
    try:
        return str(uuidlib.UUID(value.strip()))
    except ValueError as exc:
        raise IdentityValidationError("invalid UUID/GUID") from exc


def _valid_fingerprint(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool, list, dict)):
        raise IdentityValidationError("browser fingerprint must be JSON data")
    if isinstance(value, dict) and not all(isinstance(key, str) for key in value):
        raise IdentityValidationError("browser fingerprint object keys must be strings")
    if isinstance(value, list) and any(isinstance(item, dict) and not all(isinstance(key, str) for key in item) for item in value):
        raise IdentityValidationError("browser fingerprint object keys must be strings")
    try:
        encoded = _canonical(value)
    except Exception as exc:
        raise IdentityValidationError("browser fingerprint is not JSON-serializable") from exc
    if len(encoded) > 64 * 1024:
        raise IdentityValidationError("browser fingerprint exceeds 64 KiB")
    if isinstance(value, dict):
        return dict(sorted((str(key), item) for key, item in value.items()))
    return value


def _valid_gps(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise IdentityValidationError("GPS data must be an object")
    if not all(isinstance(key, str) for key in value):
        raise IdentityValidationError("GPS data keys must be strings")
    result: dict[str, Any] = {}
    for name in ("latitude", "longitude"):
        if name not in value:
            raise IdentityValidationError(f"GPS data missing {name}")
        try:
            if isinstance(value[name], bool):
                raise TypeError
            result[name] = float(value[name])
        except (TypeError, ValueError) as exc:
            raise IdentityValidationError(f"GPS {name} is not numeric") from exc
    if not -90.0 <= result["latitude"] <= 90.0:
        raise IdentityValidationError("GPS latitude is outside [-90, 90]")
    if not -180.0 <= result["longitude"] <= 180.0:
        raise IdentityValidationError("GPS longitude is outside [-180, 180]")
    for name, minimum, maximum in (
        ("altitude_m", -10000.0, 100000.0),
        ("accuracy_m", 0.0, 1000000.0),
    ):
        if name in value and value[name] is not None:
            try:
                if isinstance(value[name], bool):
                    raise TypeError
                number = float(value[name])
            except (TypeError, ValueError) as exc:
                raise IdentityValidationError(f"GPS {name} is not numeric") from exc
            if not minimum <= number <= maximum:
                raise IdentityValidationError(f"GPS {name} is outside the accepted range")
            result[name] = number
    if "timestamp" in value and value["timestamp"] is not None:
        if not isinstance(value["timestamp"], str):
            raise IdentityValidationError("GPS timestamp must be a string")
        try:
            parsed_timestamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise IdentityValidationError("GPS timestamp must be RFC 3339") from exc
        if parsed_timestamp.tzinfo is None:
            raise IdentityValidationError("GPS timestamp must include a timezone")
        result["timestamp"] = value["timestamp"]
    encoded = _canonical(result)
    if len(encoded) > 4096:
        raise IdentityValidationError("GPS data exceeds 4 KiB")
    return result


@dataclass(frozen=True)
class IdentityRecord:
    ip_address: str | None = None
    mac_address: str | None = None
    hardware_serial: str | None = None
    uuid: str | None = None
    guid: str | None = None
    browser_fingerprint: Any = None
    wifi_bssid: str | None = None
    gps: dict[str, Any] | None = None
    additional: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_payload(self) -> bytes:
        return _canonical(self.to_dict())

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> IdentityRecord:
        if not isinstance(data, Mapping):
            raise IdentityValidationError("identity input must be a JSON object")
        normalized_keys: dict[Any, Any] = {}
        for key, value in data.items():
            normalized = key.strip() if isinstance(key, str) else key
            if normalized in normalized_keys:
                raise IdentityValidationError("identity input contains duplicate normalized keys")
            normalized_keys[normalized] = value
        ip_value = _first(normalized_keys, _IP_ALIASES)
        mac_value = _first(normalized_keys, _MAC_ALIASES)
        bssid_value = _first(normalized_keys, _BSSID_ALIASES)
        serial_value = _first(normalized_keys, _SERIAL_ALIASES)
        uuid_value = _first(normalized_keys, _UUID_ALIASES)
        guid_value = _first(normalized_keys, _GUID_ALIASES)
        fingerprint_value = _first(normalized_keys, _FINGERPRINT_ALIASES)
        gps_value = _first(normalized_keys, _GPS_ALIASES)

        known = set(_IP_ALIASES + _MAC_ALIASES + _BSSID_ALIASES + _SERIAL_ALIASES + _UUID_ALIASES + _GUID_ALIASES + _FINGERPRINT_ALIASES + _GPS_ALIASES)
        additional: dict[str, Any] = {}
        for key, value in normalized_keys.items():
            if key in known:
                continue
            if key == "additional":
                if not isinstance(value, Mapping):
                    raise IdentityValidationError("additional identity data must be an object")
                for subkey, subvalue in value.items():
                    if not isinstance(subkey, str):
                        raise IdentityValidationError("additional identity data keys must be strings")
                    additional[subkey] = subvalue
            elif isinstance(key, str):
                additional[key] = value
            else:
                raise IdentityValidationError("additional identity data keys must be strings")
        try:
            encoded = _canonical(additional)
        except Exception as exc:
            raise IdentityValidationError("additional identity data is not JSON-serializable") from exc
        if len(encoded) > 64 * 1024:
            raise IdentityValidationError("additional identity data exceeds 64 KiB")

        return cls(
            ip_address=_valid_ip(ip_value) if ip_value is not None else None,
            mac_address=_valid_mac(mac_value) if mac_value is not None else None,
            hardware_serial=_valid_serial(serial_value) if serial_value is not None else None,
            uuid=_valid_uuid(uuid_value) if uuid_value is not None else None,
            guid=_valid_uuid(guid_value) if guid_value is not None else None,
            browser_fingerprint=_valid_fingerprint(fingerprint_value),
            wifi_bssid=_valid_mac(bssid_value) if bssid_value is not None else None,
            gps=_valid_gps(gps_value),
            additional=additional,
        )

    @classmethod
    def from_json(cls, value: str | bytes) -> IdentityRecord:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise IdentityValidationError("identity input contains duplicate JSON keys")
                result[key] = item
            return result

        def reject_constant(_: str) -> None:
            raise IdentityValidationError("identity input contains a non-finite number")

        try:
            parsed = json.loads(
                value,
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            )
        except IdentityValidationError:
            raise
        except Exception as exc:
            raise IdentityValidationError("identity input is not valid JSON") from exc
        return cls.from_mapping(parsed)


def validate_identity(data: Mapping[str, Any]) -> IdentityRecord:
    """Validate sensitive identity data without echoing it in errors."""
    return IdentityRecord.from_mapping(data)
