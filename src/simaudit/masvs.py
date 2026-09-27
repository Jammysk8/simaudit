"""MASVS v2 control definitions used for finding classification."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MasvsCategory(str, Enum):
    STORAGE = "MASVS-STORAGE"
    CRYPTO = "MASVS-CRYPTO"
    AUTH = "MASVS-AUTH"
    NETWORK = "MASVS-NETWORK"
    PLATFORM = "MASVS-PLATFORM"
    CODE = "MASVS-CODE"
    RESILIENCE = "MASVS-RESILIENCE"


# Control ID → (title, category, default severity)
CONTROLS: dict[str, tuple[str, MasvsCategory, Severity]] = {
    # STORAGE
    "MASVS-STORAGE-1": (
        "Sensitive data is only stored internally, following the best practices and recommendations",
        MasvsCategory.STORAGE,
        Severity.HIGH,
    ),
    "MASVS-STORAGE-2": (
        "Sensitive data is not stored in publicly accessible locations",
        MasvsCategory.STORAGE,
        Severity.HIGH,
    ),
    # CRYPTO
    "MASVS-CRYPTO-1": (
        "The app employs current strong cryptography and uses it according to industry best practices",
        MasvsCategory.CRYPTO,
        Severity.HIGH,
    ),
    "MASVS-CRYPTO-2": (
        "The app performs key management according to industry best practices",
        MasvsCategory.CRYPTO,
        Severity.HIGH,
    ),
    # PLATFORM
    "MASVS-PLATFORM-1": (
        "The app uses IPC mechanisms securely",
        MasvsCategory.PLATFORM,
        Severity.MEDIUM,
    ),
    "MASVS-PLATFORM-2": (
        "The app uses WebViews securely",
        MasvsCategory.PLATFORM,
        Severity.HIGH,
    ),
    "MASVS-PLATFORM-3": (
        "The app uses third-party components securely",
        MasvsCategory.PLATFORM,
        Severity.MEDIUM,
    ),
    # CODE
    "MASVS-CODE-1": (
        "The app requires an up-to-date platform version",
        MasvsCategory.CODE,
        Severity.LOW,
    ),
    "MASVS-CODE-2": (
        "The app has a mechanism for enforcing app updates",
        MasvsCategory.CODE,
        Severity.LOW,
    ),
    "MASVS-CODE-3": (
        "The app only uses software components without known vulnerabilities",
        MasvsCategory.CODE,
        Severity.MEDIUM,
    ),
    "MASVS-CODE-4": (
        "The app is configured following security best practices for its release build",
        MasvsCategory.CODE,
        Severity.MEDIUM,
    ),
    # NETWORK
    "MASVS-NETWORK-1": (
        "The app secures all network traffic according to the current best practices",
        MasvsCategory.NETWORK,
        Severity.HIGH,
    ),
    "MASVS-NETWORK-2": (
        "The app performs identity pinning for all remote endpoints under the developer's control",
        MasvsCategory.NETWORK,
        Severity.MEDIUM,
    ),
    # AUTH
    "MASVS-AUTH-1": (
        "The app uses secure authentication and authorization protocols",
        MasvsCategory.AUTH,
        Severity.HIGH,
    ),
    "MASVS-AUTH-2": (
        "The app applies the principle of least privilege to its credentials",
        MasvsCategory.AUTH,
        Severity.MEDIUM,
    ),
}


def control(control_id: str) -> dict:
    """Return a dict describing a MASVS control, or a minimal unknown placeholder."""
    if control_id in CONTROLS:
        title, category, default_severity = CONTROLS[control_id]
        return {
            "id": control_id,
            "title": title,
            "category": category.value,
            "default_severity": default_severity.value,
        }
    return {
        "id": control_id,
        "title": "Unknown control",
        "category": "UNKNOWN",
        "default_severity": Severity.INFO.value,
    }
