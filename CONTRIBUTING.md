# Contributing to IoT Hunter

Thank you for your interest in improving IoT Hunter. This project is a defensive IoT security toolkit, and contributions should preserve its authorized-use, non-destructive, and defensive focus.

By contributing, you agree that your contributions will be licensed under the project's **GNU GPL-3.0** license.

## Scope and Ethical Boundaries

IoT Hunter is intended for authorized assessment of devices and private networks that the operator owns or has explicit written permission to test.

Contributions must NOT add or enable:

- Credential brute-forcing or default-credential guessing as a default behavior
- Exploit code, payload delivery, persistence, or destructive actions
- Unauthorized access, account takeover, or device disruption
- Covert exfiltration of data from devices or networks
- Scanning of public/non-private IP ranges beyond the project's existing safeguards

Protocol checks must remain **read-only or non-destructive by default**. Any write operation must be explicitly opt-in, clearly documented, and require authorization confirmation.

## Ways to Contribute

- Bug reports
- Feature proposals
- Documentation improvements
- New defensive audit modules
- Tests and test fixtures
- GUI/UX improvements
- Report output improvements (PDF, JSON, SARIF, etc.)

## Before You Start

1. Search existing issues and pull requests to avoid duplicate work.
2. For large changes or new modules, open an issue first describing:
   - The problem being solved
   - Proposed behavior
   - Files/modules you expect to touch
   - Ethical and safety considerations
   - Testing approach
3. For small fixes and documentation changes, you can open a pull request directly.

## Development Setup

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR-USERNAME/iot-hunter.git
cd iot-hunter

git remote add upstream https://github.com/mrcyberharsh/iot-hunter.git

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python -m unittest discover -s tests -v
```

Create a feature branch:

```bash
git checkout -b feature/short-description
```

Use descriptive branch names, for example:

- `feature/tls-audit-module`
- `fix/inventory-diff-missing-device`
- `docs/update-scan-profiles`

## Coding Guidelines

- Target **Python 3.10+**.
- Follow PEP 8 where practical.
- Prefer clear, small functions and explicit error handling.
- Use the existing `logging` patterns instead of `print()` for runtime output.
- Add new configuration options to `config.yaml` with safe defaults.
- Keep modules under `modules/` and follow the existing module interface patterns.
- Do not hardcode credentials, API keys, private IPs, or device-specific secrets.
- Preserve existing safeguards:
  - Authorization confirmation in the desktop scanner
  - Private IPv4 range limits up to `/24`
  - Non-destructive defaults
- Handle network timeouts, permission errors, and unavailable optional dependencies gracefully.
- Update the README when behavior, configuration, or usage changes.

## Tests

- Add unit tests for new modules and bug fixes.
- Use the existing `unittest` framework under `tests/`.
- Tests must not require live network access or real devices.
- Mock sockets, subprocess calls, packet capture, and external services.
- Sanitize all fixtures — no real MAC addresses, private IP inventories, credentials, or packet captures.
- Run the full suite before opening a pull request:

```bash
python -m unittest discover -s tests -v
```

If your change affects the GUI or reporting, include a brief manual test note in the PR.

## Commit Messages

Use clear, imperative commit messages:

```text
Add TLS certificate hygiene audit module
Fix inventory diff for missing devices
Update README scan profile documentation
```

Keep commits focused. Avoid mixing unrelated changes in one commit or pull request.

## Pull Request Process

1. Sync with upstream before opening your PR:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

2. Rebase or merge `main` into your feature branch if needed.
3. Open a pull request from your fork to the upstream `main` branch.
4. In the PR description include:
   - What changed and why
   - Related issue number, if any
   - How you tested it
   - Any configuration or documentation changes
   - Any security or ethical considerations
5. Keep the PR focused on one feature or fix.
6. Respond to review feedback and update the branch as needed.

Do not include sensitive data in PRs, including:

- Real network inventories
- Private IP addresses
- MAC addresses
- Credentials or tokens
- Packet captures
- Device serial numbers or firmware dumps

## Reporting Bugs

Open an issue with:

- OS and Python version
- IoT Hunter version/commit
- Module or command used
- Expected behavior
- Actual behavior
- Sanitized logs or error output
- Whether optional dependencies such as Npcap/libpcap are installed

## Feature Proposals

Open an issue describing:

- The defensive use case
- Why existing checks are insufficient
- Proposed module or configuration changes
- Whether the feature is active, passive, or hybrid
- Safety and authorization implications
- Test plan

## Security Vulnerabilities

Do not open a public issue for security vulnerabilities in IoT Hunter itself. Contact the maintainer privately through the contact information on their GitHub profile and allow time for a fix before public disclosure.

## Documentation

- Keep README instructions accurate.
- Document new configuration options in `config.yaml` and the README.
- Clearly label experimental or optional features.
- Preserve the project's authorization and safe-operation warnings.

## License

By contributing, you confirm that you have the right to submit the contribution and that it may be distributed under the project's **GNU GPL-3.0** license.
