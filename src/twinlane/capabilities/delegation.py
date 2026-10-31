"""Monotonic attenuation verification for delegated capability tokens."""

from typing import Any

from twinlane.capabilities.token import CapabilityToken
from twinlane.protocol.errors import AttenuationViolationError


def verify_attenuation(parent: CapabilityToken, child: CapabilityToken) -> None:
    """Verify that a delegated child token strictly narrows the parent token's authority.

    Guarantees the Invariant of Monotonic Attenuation:
    1. Child must reference parent token ID.
    2. Child issuer must match parent subject.
    3. Child intents must be a strict subset of parent intents.
    4. Child parameter constraints cannot widen parent constraints.
    5. Child temporal window must be bounded by parent window.
    6. Child max_uses cannot exceed remaining parent uses.

    Raises:
        AttenuationViolationError: If any condition fails.
    """
    # 1. Reference check
    if child.parent_token_id != parent.token_id:
        raise AttenuationViolationError(
            f"Child parent_token_id '{child.parent_token_id}' does not match parent ID '{parent.token_id}'"
        )

    # 2. Issuer check
    if child.issuer.lower() != parent.subject.lower():
        raise AttenuationViolationError(
            f"Child issuer '{child.issuer}' must be parent subject '{parent.subject}'"
        )

    # 3. Intent narrowing
    parent_intents = set(parent.intents)
    child_intents = set(child.intents)
    if not child_intents.issubset(parent_intents):
        widened = child_intents - parent_intents
        raise AttenuationViolationError(
            f"Child attempts to grant unauthorized intents: {sorted(widened)}"
        )

    # 4. Temporal narrowing
    if child.not_before < parent.not_before:
        raise AttenuationViolationError(
            f"Child not_before ({child.not_before}) cannot precede parent not_before ({parent.not_before})"
        )
    if child.expires_at > parent.expires_at:
        raise AttenuationViolationError(
            f"Child expires_at ({child.expires_at}) exceeds parent expires_at ({parent.expires_at})"
        )

    # 5. Usage quota narrowing
    remaining_parent_uses = max(0, parent.max_uses - parent.uses_count)
    if child.max_uses > remaining_parent_uses:
        raise AttenuationViolationError(
            f"Child max_uses ({child.max_uses}) exceeds remaining parent uses ({remaining_parent_uses})"
        )

    # 6. Constraint narrowing
    for intent, p_constraints in parent.constraints.items():
        if intent not in child.constraints:
            continue
        c_constraints = child.constraints[intent]
        _verify_constraint_narrowing(intent, p_constraints, c_constraints)


def _verify_constraint_narrowing(
    intent: str,
    parent_rules: dict[str, Any],
    child_rules: dict[str, Any],
) -> None:
    """Ensure child constraints do not widen parent rules for a specific intent."""
    for rule_key, p_val in parent_rules.items():
        if rule_key.endswith("_allowlist") and rule_key in child_rules:
            c_val = child_rules[rule_key]
            if (
                isinstance(p_val, list)
                and isinstance(c_val, list)
                and not set(c_val).issubset(set(p_val))
            ):
                widened = set(c_val) - set(p_val)
                raise AttenuationViolationError(
                    f"Child allowlist for '{intent}.{rule_key}' widens allowed items: {sorted(widened)}"
                )
        elif rule_key.endswith("_max") and rule_key in child_rules:
            c_val = child_rules[rule_key]
            if (
                isinstance(p_val, (int, float))
                and isinstance(c_val, (int, float))
                and c_val > p_val
            ):
                raise AttenuationViolationError(
                    f"Child limit for '{intent}.{rule_key}' ({c_val}) exceeds parent limit ({p_val})"
                )
        elif rule_key.endswith("_prefix") and rule_key in child_rules:
            c_val = str(child_rules[rule_key])
            p_str = str(p_val)
            if not c_val.startswith(p_str):
                raise AttenuationViolationError(
                    f"Child prefix '{c_val}' does not narrow parent prefix '{p_str}' for '{intent}'"
                )
