from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from safegate.rules.base import Severity

RULE_IDS = (
    "SG-001",
    "SG-002",
    "SG-003",
    "SG-004",
    "SG-005",
    "SG-006",
    "SG-007",
    "SG-008",
    "SG-009",
    "SG-010",
)
_ROOT_KEYS = {"pg_version", "transactional", "rules"}
_RULE_KEYS = {"enabled", "severity", "allowlist"}


class ConfigError(ValueError):
    """Raised when `.safegate.toml` is invalid or contains unknown keys."""


@dataclass(frozen=True, slots=True)
class RuleConfig:
    enabled: bool = True
    severity: Severity | None = None
    allowlist: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SafegateConfig:
    pg_version: int = 16
    transactional: bool = True
    rules: Mapping[str, RuleConfig] = field(default_factory=dict)


def _require_bool(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _parse_severity(value: object, rule_id: str) -> Severity | None:
    if value is None:
        return None
    if value == "low":
        return "low"
    if value == "medium":
        return "medium"
    if value == "high":
        return "high"
    raise ConfigError(f"rules.{rule_id}.severity must be low, medium, or high")


def load_config(
    path: str | Path = ".safegate.toml",
    *,
    pg_version_override: int | None = None,
) -> SafegateConfig:
    config_path = Path(path)
    if not config_path.exists():
        data: dict[str, object] = {}
    else:
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ConfigError(f"could not read {config_path}: {error}") from error

    unknown = set(data) - _ROOT_KEYS
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")

    pg_version = data.get("pg_version", 16)
    if (
        isinstance(pg_version, bool)
        or not isinstance(pg_version, int)
        or pg_version < 1
    ):
        raise ConfigError("pg_version must be a positive integer")

    transactional = _require_bool(data.get("transactional", True), "transactional")
    raw_rules = data.get("rules", {})
    if not isinstance(raw_rules, dict):
        raise ConfigError("rules must be a table")

    rules: dict[str, RuleConfig] = {}
    for rule_id, raw_rule in raw_rules.items():
        if rule_id not in RULE_IDS:
            raise ConfigError(f"unknown rule id in config: {rule_id}")
        if not isinstance(raw_rule, dict):
            raise ConfigError(f"rules.{rule_id} must be a table")
        unknown_rule_keys = set(raw_rule) - _RULE_KEYS
        if unknown_rule_keys:
            raise ConfigError(
                f"unknown config key(s) in rules.{rule_id}: "
                f"{', '.join(sorted(unknown_rule_keys))}"
            )

        enabled = _require_bool(
            raw_rule.get("enabled", True), f"rules.{rule_id}.enabled"
        )
        severity = _parse_severity(raw_rule.get("severity"), rule_id)
        allowlist_value = raw_rule.get("allowlist", [])
        if not isinstance(allowlist_value, list) or not all(
            isinstance(item, str) and item for item in allowlist_value
        ):
            raise ConfigError(
                f"rules.{rule_id}.allowlist must be an array of object names"
            )
        rules[rule_id] = RuleConfig(
            enabled=enabled,
            severity=severity,
            allowlist=tuple(sorted(set(allowlist_value))),
        )

    result = SafegateConfig(
        pg_version=pg_version,
        transactional=transactional,
        rules=rules,
    )
    if pg_version_override is not None:
        if (
            isinstance(pg_version_override, bool)
            or not isinstance(pg_version_override, int)
            or pg_version_override < 1
        ):
            raise ConfigError("--pg-version must be a positive integer")
        result = replace(result, pg_version=pg_version_override)
    return result
