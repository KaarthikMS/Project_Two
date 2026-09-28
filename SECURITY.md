# Security & Governance: Containerized & Hybrid Scanners

Running security scanners via containers and native Python introduces its own set of risks. This document outlines the security considerations and best practices for our hybrid orchestrator architecture.

## 1. Hybrid Orchestration Model

Project_Two uses a **hybrid execution model** where heavy external tools run in Docker containers and lightweight analysis tools run natively in Python:

| Type | Scanners | Isolation |
|:---|:---|:---|
| **Docker** | ZAP, Nuclei, Nmap, MobSF | Full container isolation |
| **Python** | Semgrep, Secrets, Dependency, Desktop Binary | Process-level isolation |

### Parallel Execution Isolation
- **Parallel Orchestrator**: Uses a `ThreadPoolExecutor` to run scanners concurrently. 
- **Docker Isolation**: Every Docker-based scan job uses a unique container suffix (e.g., `zap_${scan_id[:8]}`) to prevent volume contention and port collisions during parallel runs.
- **Python Thread Safety**: Sequential pre-loading of Python modules ensures that concurrent scanner imports do not cause deadlocks.

### Why Hybrid?
- **Docker scanners** (ZAP, Nuclei, Nmap) require complex dependencies or privileged access. They are executed in isolated, ephemeral containers.
- **Python scanners** (Semgrep, Secrets) are lightweight and run within the project's virtual environment, providing high throughput for static analysis.

## 2. Elevated Permissions and Nmap

Certain security tools, most notably network scanners like Nmap, require elevated system permissions to perform specialized operations (e.g., crafting raw packets for SYN scans, OS detection, or MAC address spoofing).

### The Risk
Running Docker containers with the `--privileged` flag or granting `CAP_NET_RAW` gives the container root-level bypasses over standard container isolation mechanisms. If a vulnerability exists in the scanner software, an attacker could potentially break out of the container and compromise the host runner.

### Mitigation Strategies

-   **Minimize Scope**: Only grant the specific capabilities needed. Instead of `--privileged`, try explicitly adding `CAP_NET_RAW` to the Nmap container.
    ```yaml
    # docker-compose example
    cap_add:
      - NET_RAW
      - NET_ADMIN
    ```
-   **Dedicated Runners**: In a CI/CD environment, jobs that require elevated privileges should be isolated to dedicated runners that are ephemeral and do not share state or network access with critical internal infrastructure.
-   **User Namespaces**: Utilize Docker User Namespaces to remap the root user inside the container to a less privileged user on the host.

## 3. MobSF Security Considerations

The **OWASP MobSF** container exposes a REST API for mobile app analysis. Secure this endpoint:

-   **API Key Authentication**: Always set `MOBSF_API_KEY` environment variable. Never expose MobSF without authentication.
-   **Network Isolation**: Run MobSF on an internal Docker network (`secnet`). Do not expose port 8000/8010 to the public internet.
-   **Ephemeral Data**: MobSF stores uploaded APK/IPA files internally. Use ephemeral containers (`--rm`) to prevent data accumulation.
-   **File Validation**: The `MobSFScanner` only uploads files with validated extensions (`.apk`, `.ipa`, `.xapk`, `.apks`, `.aar`).

## 4. Desktop Binary Scanner (CAPA + LIEF)

The `DesktopBinaryScanner` analyzes Windows PE, macOS Mach-O, and Linux ELF binaries using Mandiant CAPA and LIEF:

-   **CAPA Execution**: CAPA runs as a subprocess with a 300-second timeout. It does not require network access.
-   **File Size Limits**: The string analysis layer reads a maximum of 5MB per binary to prevent memory exhaustion.
-   **No Code Execution**: Both CAPA and LIEF perform static analysis only — they never execute the target binary.

## 5. Container Security Best Practices

When integrating scanner images (`projectdiscovery/nuclei`, `softwaresecurityproject/zap-stable`, etc.):

-   **Image Provenance**: Standardize on official images from trusted vendors or certified repositories (e.g., `ghcr.io/zaproxy/zaproxy:stable`).
-   **Immutable Tags**: Avoid using `:latest` tags in CI/CD pipelines. Pin images to specific SHAs or stable version tags.
-   **Read-Only Root Filesystem**: Run scanner containers with `--read-only` wherever possible.
-   **Non-Root Execution**: Configure the container to run as a non-root user if the tool supports it.
-   **Resource Limits**: Set memory and CPU limits on containers to prevent DoS on the CI runner.

## 6. Data Handling and Output Normalization

The `ScannerManager` orchestrator handles the output from all tools:

-   **Ephemeral Storage**: Reports written to protected directories (e.g., `backend/reports/poc_demo`) should be treated as ephemeral. The orchestrator ingests, processes, and securely stores the normalized data, then purges raw files.
-   **Credential Redaction**: The Secrets Scanner automatically redacts detected credentials in output (showing only first 2 and last 2 characters).

## 7. Internal Security Intelligence & RAG Governance

The transition to an AI Security Intelligence platform introduces a RAG layer. To secure this layer:

-   **Authoritative Data Only**: The Knowledge Base (ChromaDB) is populated only with vetted, authoritative datasets (CVE, CWE, OWASP, etc.).
-   **Data Privacy (No Scanner Embedding)**: Scanner results are **NOT embedded** into the vector database. This prevents sensitive target data from persisting in the Knowledge Base.
-   **Hallucination Mitigation**: By providing authoritative context in the LLM prompt, we significantly reduce AI hallucinations.
-   **Vector Store Isolation**: The vector store should be isolated and protected. In production, use encrypted storage and restrict network access.
