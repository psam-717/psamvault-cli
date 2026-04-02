# Contributing to psamvault

Thank you for your interest in contributing! This guide will get you set up locally and explain how to submit changes.

---

## Prerequisites

- Python 3.11 or higher
- [pipx](https://pipx.pypa.io) for running the CLI
- [git](https://git-scm.com)

---

## Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/psam-717/psamvault-cli
cd psamvault-cli/cli

# 2. Create and activate a virtual environment
python -m venv cli_venv
# Windows
.\cli_venv\Scripts\activate
# macOS/Linux
source cli_venv/bin/activate

# 3. Install dependencies in editable mode
pip install -e .
```

You can now run the CLI directly:

```bash
python main.py --help
python main.py --version
```

Or install it as a global command via pipx (editable):

```bash
pipx install -e .
psamvault --help
```

---

## Configure for local development

Run once after setup to generate your local pepper and point to the API:

```bash
psamvault configure
```

> ⚠️ The `~/.psamvault/config.env` file contains your pepper — never commit it. It is already listed in `.gitignore`.

---

## Project Structure

```
cli/
├── main.py              # CLI entrypoint, registers all commands
├── api_client.py        # HTTP client (wraps httpx)
├── config.py            # Loads ~/.psamvault/config.env
├── crypto.py            # Encryption / key derivation logic
├── session.py           # Local session management
├── spinner.py           # Terminal spinner utility
├── command/
│   ├── auth_commands.py     # login, logout, signup, whoami, configure
│   ├── vault_commands.py    # add, get, list, update, delete, generate
│   └── recovery_commands.py # generate-codes, remaining-codes, recover
├── pyproject.toml       # Package metadata and dependencies
└── README.md
```

---

## Making Changes

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** and test them locally.

3. **Commit** with a clear, conventional commit message:
   ```
   feat(vault): add --clipboard flag to get command
   fix(crypto): handle missing kdf_salt gracefully
   docs(README): add troubleshooting section
   ```

4. **Push** and open a Pull Request against `main`.

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org):

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change with no feature/fix |
| `chore` | Maintenance (deps, config) |
| `test` | Adding or updating tests |

---

## Security

If you find a security vulnerability, **do not open a public issue**. Please report it privately via [GitHub Security Advisories](https://github.com/psam-717/psamvault-cli/security/advisories/new).

---

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use Python type hints where practical
- Keep functions focused and small
