"""Deterministic Policy Engine enforcing intent parameters, allowlists, and provenance rules."""

import re
from typing import Any

from twinlane.gate.extractors import ExtractorRegistry
from twinlane.policy.decisions import Decision, GateDecision
from twinlane.policy.loader import ParameterRule, PolicyConfig
from twinlane.protocol.control import ControlLane
from twinlane.protocol.envelope import Header
from twinlane.protocol.provenance import IntegrityLabel


class PolicyEngine:
    """Evaluates control lane parameters and data provenance against declarative policy rules."""

    def __init__(
        self,
        config: PolicyConfig,
        extractor_registry: ExtractorRegistry | None = None,
    ) -> None:
        self.config = config
        self.mode = config.mode.lower()  # strict | balanced | observe
        self.extractors = extractor_registry or ExtractorRegistry()

    def evaluate(
        self,
        header: Header,
        control: ControlLane,
        param_labels: dict[str, IntegrityLabel] | None = None,
    ) -> GateDecision:
        """Evaluate an envelope's control intent against the policy.

        Args:
            header: Message header.
            control: Control lane command.
            param_labels: Optional mapping of parameter name to its integrity label.

        Returns:
            GateDecision: ALLOW, DENY, or ESCALATE.
        """
        violations: list[str] = []
        labels = param_labels or {}

        # 1. Check intent registered in policy
        if control.intent not in self.config.intents:
            return GateDecision.deny(
                f"Intent '{control.intent}' is not permitted by policy",
                violations=[f"Intent '{control.intent}' not in policy catalog"],
            )

        intent_rule = self.config.intents[control.intent]

        # 2. Check allowed senders
        if (
            "*" not in intent_rule.allowed_senders
            and header.sender not in intent_rule.allowed_senders
        ):
            violations.append(
                f"Sender '{header.sender}' not in allowed senders: {intent_rule.allowed_senders}"
            )

        # 3. Check parameter constraints
        for param_name, param_val in control.params.items():
            if param_name in intent_rule.parameters:
                p_rule = intent_rule.parameters[param_name]
                p_label = labels.get(param_name, IntegrityLabel.TRUSTED)
                self._validate_parameter(param_name, param_val, p_rule, p_label, violations)

        if violations:
            if self.mode == "observe":
                # In observe mode, log the violation but return ALLOW for benchmarking
                return GateDecision(
                    decision=Decision.ALLOW,
                    reason="OBSERVE_MODE_ALLOWED",
                    violations=violations,
                )
            return GateDecision.deny("Policy constraint violation", violations=violations)

        return GateDecision.allow("Policy checks passed")

    def _validate_parameter(
        self,
        param_name: str,
        val: Any,
        rule: ParameterRule,
        label: IntegrityLabel,
        violations: list[str],
    ) -> None:
        """Validate a single parameter against its schema and provenance requirements."""
        val_str = str(val)

        # Provenance check
        if self.mode == "strict":
            if label != IntegrityLabel.TRUSTED:
                violations.append(
                    f"Parameter '{param_name}' is derived from {label} data; rejected in strict mode"
                )
                return
        elif self.mode == "balanced" and label == IntegrityLabel.UNTRUSTED:
            violations.append(
                f"Parameter '{param_name}' has raw UNTRUSTED provenance without sanctioned extraction"
            )
            return

        # Pattern check
        if rule.pattern and not re.fullmatch(rule.pattern, val_str):
            violations.append(
                f"Parameter '{param_name}' value '{val_str}' does not match regex '{rule.pattern}'"
            )

        # Max length check
        if rule.max_length and len(val_str) > rule.max_length:
            violations.append(
                f"Parameter '{param_name}' length ({len(val_str)}) exceeds maximum {rule.max_length}"
            )

        # Enum check
        if rule.enum and val_str not in rule.enum:
            violations.append(
                f"Parameter '{param_name}' value '{val_str}' not in enum: {rule.enum}"
            )

        # Allowlist check
        if rule.allowlist and val_str not in rule.allowlist:
            violations.append(
                f"Parameter '{param_name}' value '{val_str}' not in allowlist: {rule.allowlist}"
            )

        # Numeric bounds
        if isinstance(val, (int, float)):
            if rule.min_value is not None and val < rule.min_value:
                violations.append(
                    f"Parameter '{param_name}' value {val} is below minimum {rule.min_value}"
                )
            if rule.max_value is not None and val > rule.max_value:
                violations.append(
                    f"Parameter '{param_name}' value {val} exceeds maximum {rule.max_value}"
                )
