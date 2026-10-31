# Contributing to TwinLane

Thank you for contributing to TwinLane. We adhere to rigorous engineering and scientific standards.

---

## 1. Standing Engineering Standards

Before submitting a Pull Request, verify that your changes adhere to our core standards in [AGENTS.md](AGENTS.md):
1. **Python 3.12+ Compatibility**: Code must run seamlessly on Python 3.12 and 3.13.
2. **Strict Typing**: Every module, class, and function must be fully typed. `mypy --strict` must pass with zero errors.
3. **Linting and Formatting**: `ruff check` and `ruff format` must pass without warnings or overrides.
4. **Security Critical Code**: Code in `crypto/`, `gate/`, `policy/`, `capabilities/`, and `protocol/` must maintain >= 90% branch and line coverage.
5. **No External Network Dependencies in Unit Tests**: Unit and property tests must execute offline using mock adapters.
6. **Architectural Decisions**: Any non-trivial design choice requires an Architectural Decision Record (ADR) in `docs/adr/`.

---

## 2. Development Workflow

```bash
# 1. Install development dependencies
pip install -e ".[dev]"

# 2. Run linting and type checking
ruff check src/ tests/
ruff format --check src/ tests/
mypy --strict src/ tests/

# 3. Run test suite
pytest --cov=twinlane --cov-report=term-missing
```

---

## 3. Conventional Commits

Commit messages must follow the Conventional Commits specification:
- `feat(protocol)`: New protocol feature or envelope field.
- `fix(gate)`: Bug fix in Gate pipeline or validation logic.
- `test(security)`: Addition of new security or property tests.
- `docs(spec)`: Updates to protocol specifications or research docs.
