# Installing vaultmap — many ways, every platform

`vaultmap` is Python 3.10+ and **standard-library only**, so it runs anywhere. Pick whatever fits your stack:

| Method | Command |
|---|---|
| **pip** (from source — works today) | `pip install "git+https://github.com/cognis-digital/vaultmap.git"` |
| **pipx** (isolated CLI) | `pipx install "git+https://github.com/cognis-digital/vaultmap.git"` |
| **uv** (fast) | `uv tool install "git+https://github.com/cognis-digital/vaultmap.git"` |
| **pip / PyPI** (when published) | `pip install cognis-vaultmap` |
| **Homebrew** (tap) | `brew install cognis-digital/tap/vaultmap` |
| **Docker** | `docker run --rm ghcr.io/cognis-digital/vaultmap:latest --help` |
| **curl \| sh** (one-liner) | `curl -fsSL https://raw.githubusercontent.com/cognis-digital/vaultmap/main/install.sh \| sh` |
| **from clone** | `git clone https://github.com/cognis-digital/vaultmap && cd vaultmap && pip install -e ".[dev]"` |
| **Dev Container** | open in VS Code → *Reopen in Container* |
| **Linux / macOS / Windows** | `scripts/setup-linux.sh` · `scripts/setup-macos.sh` · `scripts/setup-windows.ps1` |
| **Cloud (AWS/Azure/GCP/k8s)** | see [`docs/DEPLOY.md`](docs/DEPLOY.md) |

Other language ports (JS / Go / Rust) live in [`ports/`](ports/).

> PyPI/Homebrew names are reserved for release; the `git+https` forms work right now.
