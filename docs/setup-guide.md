# Development Environment Setup Guide

**DNS Mastery Curriculum — macOS (Homebrew)**

---

## Core Tools

These are needed across all 12 labs.

### Python 3.12+

```bash
brew install python@3.12
python3 --version   # Verify 3.12+
```

### BIND (dig, host, nslookup)

```bash
brew install bind
dig -v              # Verify
```

### Graphviz (visual diagrams)

```bash
brew install graphviz
dot -V              # Verify
```

### Wireshark / tshark (packet analysis)

```bash
brew install --cask wireshark
tshark --version    # Verify
```

---

## Phase-Specific Tools

### Phase 1 (Weeks 1–4): Foundations

No additional tools beyond core. `dig`, Python, and Graphviz cover everything.

### Phase 2 (Weeks 5–8): Security & Attacks

```bash
# Splunk Free (local instance for detection rule testing)
# Download from: https://www.splunk.com/en_us/download/splunk-enterprise.html

# Python ML libraries (Lab 8: DGA Classifier)
pip3 install scikit-learn pandas numpy jupyter matplotlib

# Sigma rule tools
pip3 install sigma-cli
```

### Phase 3 (Weeks 9–12): Modern DNS & Defense

```bash
# BIND9 (for RPZ labs — run in a VM or container)
# Use Docker or a Linux VM for full BIND9 server testing

# Unbound (alternative resolver)
brew install unbound
```

---

## Recommended Virtual Lab Environment

For labs that involve running DNS servers or generating attack traffic (Labs 5, 6, 10), use an isolated environment:

```bash
# Option 1: Docker
docker pull ubuntu:24.04
docker run -it --name dns-lab ubuntu:24.04 /bin/bash

# Option 2: UTM (free macOS VM manager)
# Download from: https://mac.getutm.app/
# Use Ubuntu Server 24.04 LTS image
```

---

## Git Setup

```bash
cd dns-mastery
git init
git add .
git commit -m "Initial commit: repo structure + Lab 01 Hierarchy Mapper"
```

### Recommended Branching

```
main            ← Completed, tested labs only
└── dev         ← Work in progress
    ├── lab-02  ← Feature branch per lab
    ├── lab-03
    └── ...
```

---

## Editor Configuration

### VS Code (recommended extensions)

- **Python** — ms-python.python
- **Pylance** — ms-python.vscode-pylance
- **Markdown Preview Enhanced** — shd101wyy.markdown-preview-enhanced
- **Graphviz Preview** — joaompinto.vscode-graphviz

### Workspace settings

```json
{
    "python.defaultInterpreterPath": "/opt/homebrew/bin/python3",
    "editor.rulers": [100],
    "files.trimTrailingWhitespace": true,
    "[python]": {
        "editor.formatOnSave": true
    }
}
```
