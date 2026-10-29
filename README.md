# ZDU Engine

**ZDU Engine** is an enterprise-ready, multi-platform, zero-restart rolling deployment framework. It provides agentless update orchestration across hybrid infrastructure fleets, spanning **Linux (Debian/RHEL)**, **macOS**, and **Windows**. 

Designed for high-availability environments, the framework acts as a definitive protection gate. It ensures that system updates never trigger unintended reboots, bypass safety constraints, or cause cascading production outages.

---

## Key Core Mechanisms

*   **Deterministic Safety Interlock:** All mutating script execution (`--apply`) is explicitly protected by an active code fence block to prevent accidental target updates during structural test runs.
*   **Predictive Maintenance Gates:** Enforces system state resource validation (rejects deployment if CPU >85% or free RAM <10%) and parses pre-configured historical P95 metrics (e.g., maximum disk latency).
*   **Cryptographic Supply-Chain Hardening:** Automates pre- and post-deployment Software Bill of Materials (SBOM) generation, enforces valid OS/Codesign binary signatures, and mandates static SHA-256 hash pinning for critical system binaries.
*   **Automated Inbound Quarantine:** Isolates production traffic natively via system firewalls (IPTables/NFTables, `pf`, or Advanced Windows Firewall) during maintenance windows while leaving management interfaces (SSH, WinRM) operational.
*   **Progressive Canary Rollouts:** Enforces non-critical canary validation with post-deployment observation windows before executing progressive rolling batches across clusters.

---

## Directory Layout

```text
├── ZDU-Linux.sh       # Universal worker/SSH control plane for Debian/RHEL
├── ZDU-macOS.sh       # Native worker/agentless controller for macOS & Homebrew
├── ZDU-Windows.bat    # Single-file elevated launcher with embedded PowerShell engine
├── LICENSE            # MIT open-source license
├── .gitignore         # Strict patterns for logs, evidence bundles, and caches
└── README.md          # Technical documentation
```

---

## Getting Started

### 1. Linux Local Strategy Preview
Run a read-only transaction simulation, environment validation, and dependency evaluation:
```bash
sudo ./ZDU-Linux.sh --mode local --plan --config ./zdu-linux.conf
```

### 2. macOS Fleet Rollout Execution
Execute a rolling orchestration across an external network segment utilizing an explicit non-critical canary verification node:
```bash
sudo ./ZDU-macOS.sh --mode cluster --hosts production_nodes.txt --canary mac-canary-01.local --apply
```

### 3. Windows Automated Discovery & Report Generation
Inventory active system services, verify binary certificates, and generate observation-based hash configurations without making machine modifications:
```cmd
ZDU-Windows.bat -PinReport
```

---

## Technical Architecture & Guardrails

| Safety Layer | Linux Engine (`.sh`) | macOS Engine (`.sh`) | Windows Engine (`.bat`/`.ps1`) |
| :--- | :--- | :--- | :--- |
| **Privilege Model** | Local Unix root (`sudo`) | Local Unix root (`sudo`) | Elevated token context (UAC request) |
| **System Isolation** | Proxy hook drain + probe | Proxy hook drain + probe | Advanced Inbound Firewall Loopback Block |
| **Package Upgrades** | `apt-get` / `dnf` / `yum` | `softwareupdate` + `brew` | Native `winget` ID pins + WUA Session COM |
| **Snapshot Artifact**| Btrfs / ZFS / LVM snapshots | Local Time Machine snapshot | Windows System Restore point (`MODIFY_SETTINGS`) |
| **Anomaly Analytics**| `journalctl` error logs | Unified Logging Subsystem | Windows Event Log (Application Level 2) |
| **Forensics** | CMS-encrypted Tarball | CMS-encrypted Tarball | CMS-protected Zip Bundle (`Protect-CmsMessage`)|

---

## Critical Engineering Constraints

1. **Snapshots are Recovery Artifacts Only:** Underlying filesystem state capture mechanisms (APFS local snapshots, Btrfs subvolumes, Volume Shadow Checkpoints) are designed as cold-recovery artifacts. The framework explicitly blocks online root rollbacks; deep remediations require human-approved, verified `--rollback` adapter bindings.
2. **Strict Key=Value Policy Parser:** Configurations are parsed purely as data blocks. Shell expansion symbols, variable injection vectors, and command substitution flags are rejected to guarantee configuration safety.
3. **WinRM / SSH Remote Integrity:** All configurations streamed during cluster rollouts bypass volatile world-writable locations (such as `/tmp`), writing directly to root-owned run-time directory paths (`/run/zdu`, `/var/run/zdu`, or `C:\ProgramData\ZDU`) via authenticated remote pathways.
