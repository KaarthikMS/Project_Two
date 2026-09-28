"""
Desktop Binary Scanner - Windows (EXE/DLL) and macOS (Mach-O/PKG) Security Analysis.

Combines two complementary analysis engines:
1. Mandiant CAPA  — Capability detection with MITRE ATT&CK mapping
2. LIEF           — Binary hardening checks (NX, PIE, RELRO, stack canaries)

Install:
  pip install lief pefile capstone
  # CAPA: Download standalone from https://github.com/mandiant/capa/releases
  #   or: pip install flare-capa
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class DesktopBinaryScanner:
    """
    Security scanner for desktop application binaries.

    Supported formats:
    - Windows:  PE (.exe, .dll, .sys, .ocx, .scr)
    - macOS:    Mach-O (executable, .dylib, .bundle)
    - Linux:    ELF  (.so, .bin, no extension)

    Analysis layers:
    1. Binary Hardening  — NX/DEP, PIE/ASLR, RELRO, Stack Canaries, Code Signing
    2. Capability Detection (CAPA) — MITRE ATT&CK mapped behaviors
    3. Suspicious String Extraction — credentials, URLs, IP addresses
    """

    PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr"}
    MACHO_EXTENSIONS = {".dylib", ".bundle"}
    ELF_EXTENSIONS = {".so", ".bin", ".elf"}
    PKG_EXTENSIONS = {".pkg"}
    ALL_EXTENSIONS = PE_EXTENSIONS | MACHO_EXTENSIONS | ELF_EXTENSIONS | PKG_EXTENSIONS

    def __init__(self, capa_path: str | None = None, capa_rules: str | None = None):
        # Use venv-aware capa if possible
        v_capa = Path(PROJECT_ROOT) / ".venv" / "bin" / "capa"
        if not capa_path and v_capa.exists():
             self.capa_path = str(v_capa)
        else:
             self.capa_path = capa_path or os.environ.get("CAPA_PATH", "capa")
             
        default_rules = str(Path(PROJECT_ROOT) / "backend" / "scanners" / "capa-rules")
        self.capa_rules = capa_rules or os.environ.get("CAPA_RULES", default_rules)
        
        default_sigs = str(Path(PROJECT_ROOT) / "backend" / "scanners" / "capa-signatures")
        self.capa_sigs = os.environ.get("CAPA_SIGNATURES", default_sigs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> Dict[str, Any]:
        """Scan a single file or walk a directory."""
        target_path = Path(target)
        if target_path.is_file():
            if target_path.suffix.lower() == ".pkg":
                return self._scan_pkg_installer(target_path)
            return self._scan_single(target_path)
        elif target_path.is_dir():
            return self._scan_directory(target_path)
        else:
            return self._error_result(f"Target not found: {target}")

    def scan_directory(self, directory_path: str) -> Dict[str, Any]:
        """Alias used by the orchestrator."""
        return self.scan(directory_path)

    # ------------------------------------------------------------------
    # Directory walk
    # ------------------------------------------------------------------

    def _scan_directory(self, directory: Path) -> Dict[str, Any]:
        all_vulns: List[Dict] = []
        scanned = 0

        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in self.ALL_EXTENSIONS or self._is_executable(fpath):
                    result = self._scan_single(fpath)
                    all_vulns.extend(result.get("vulnerabilities", []))
                    scanned += 1

        return {
            "scanner": "desktop_binary",
            "target": str(directory),
            "files_scanned": scanned,
            "total": len(all_vulns),
            "vulnerabilities": all_vulns,
            "severity_breakdown": self._count_by_severity(all_vulns),
        }

    # ------------------------------------------------------------------
    # Single file analysis
    # ------------------------------------------------------------------

    def _scan_single(self, file_path: Path) -> Dict[str, Any]:
        logger.info("Desktop binary scan: %s", file_path)
        vulns: List[Dict] = []

        # Layer 1 — Binary hardening (LIEF)
        vulns.extend(self._check_hardening(file_path))

        # Layer 2 — Capability detection (CAPA)
        vulns.extend(self._run_capa(file_path))

        # Layer 3 — Suspicious strings
        vulns.extend(self._string_analysis(file_path))

        platform = self._detect_platform(file_path)

        return {
            "scanner": "desktop_binary",
            "target": str(file_path),
            "platform": platform,
            "total": len(vulns),
            "vulnerabilities": vulns,
            "severity_breakdown": self._count_by_severity(vulns),
        }

    def _detect_platform(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        if ext in self.PE_EXTENSIONS:
            return "windows"
        if ext in self.MACHO_EXTENSIONS or ext in self.PKG_EXTENSIONS:
            return "macos"
        if ext in self.ELF_EXTENSIONS:
            return "linux"
            
        # Magic byte check for extensionless files
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]:
                    return "macos"
                if magic == b"\x7fELF":
                    return "linux"
                if magic.startswith(b"MZ"):
                    return "windows"
        except Exception:
            pass
            
        return "linux"  # Default fallback

    # ------------------------------------------------------------------
    # macOS PKG Extraction
    # ------------------------------------------------------------------

    def _scan_pkg_installer(self, pkg_path: Path) -> Dict[str, Any]:
        """Extract and scan contents of a macOS .pkg file."""
        logger.info("Extracting and scanning macOS Installer: %s", pkg_path)
        
        with tempfile.TemporaryDirectory(prefix="mobsf_pkg_") as outer_tmp:
            try:
                # pkgutil --expand expects the destination to NOT exist or be empty
                expand_dir = Path(outer_tmp) / "expanded"
                cmd = ["pkgutil", "--expand", str(pkg_path), str(expand_dir)]
                subprocess.run(cmd, check=True, capture_output=True)
                
                # Check for Payload files and extract them
                for root, _, files in os.walk(expand_dir):
                    if "Payload" in files:
                        payload_path = Path(root) / "Payload"
                        payload_out = Path(root) / "unpacked_payload"
                        os.makedirs(payload_out, exist_ok=True)
                        # Extract cpio/gzip payload
                        # Some are gzipped, some are not. cpio handles both often or needs zcat
                        try:
                            with open(payload_path, "rb") as f:
                                # Quick check if it's gzipped
                                header = f.read(2)
                                f.seek(0)
                                if header == b"\x1f\x8b":
                                    cat_cmd = ["gunzip", "-c", str(payload_path)]
                                else:
                                    cat_cmd = ["cat", str(payload_path)]
                                
                            ps = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE)
                            subprocess.run(["cpio", "-id", "--quiet"], stdin=ps.stdout, cwd=payload_out, capture_output=True)
                            ps.wait()
                        except Exception as pe:
                            logger.warning("Failed to extract Payload in %s: %s", root, pe)

                # Scan everything expanded
                result = self._scan_directory(expand_dir)
                result["target"] = str(pkg_path)
                result["platform"] = "macos"
                return result
                
            except Exception as e:
                logger.error("Failed to expand PKG %s: %s", pkg_path, e)
                return self._error_result(f"PKG expansion failed: {e}")

    # ------------------------------------------------------------------
    # Layer 1 — Binary Hardening (LIEF)
    # ------------------------------------------------------------------

    def _check_hardening(self, file_path: Path) -> List[Dict]:
        findings: List[Dict] = []
        try:
            import lief  # type: ignore

            binary = lief.parse(str(file_path))
            if not binary:
                return []

            fstr = str(file_path)
            
            # Detect format using LIEF classes (more robust than missing EXE_FORMATS)
            if isinstance(binary, lief.PE.Binary):
                findings.extend(self._check_pe_hardening(binary, fstr))
            
            elif isinstance(binary, lief.ELF.Binary):
                findings.extend(self._check_elf_hardening(binary, fstr))
            
            elif isinstance(binary, (lief.MachO.Binary, lief.MachO.FatBinary)):
                if isinstance(binary, lief.MachO.FatBinary):
                    sub_bins = getattr(binary, "binaries", [])
                    logger.debug("LIEF: Analyzing Fat Mach-O binary with %d architectures", len(sub_bins))
                    for sub_binary in sub_bins:
                        findings.extend(self._check_macho_hardening(sub_binary, fstr))
                else:
                    findings.extend(self._check_macho_hardening(binary, fstr))
            
            else:
                logger.debug("LIEF: Unhandled binary type for %s", file_path.name)

        except ImportError:
            logger.warning("LIEF not installed. Skipping binary hardening checks.")
        except Exception as e:
            logger.debug("LIEF analysis failed for %s: %s", file_path, e)

        return findings

    def _check_pe_hardening(self, binary: Any, file_path: str) -> List[Dict]:
        findings = []

        # DEP / NX
        if hasattr(binary, "optional_header"):
            oh = binary.optional_header
            # DLL_CHARACTERISTICS.NX_COMPAT is 0x0100
            char = getattr(oh, "dll_characteristics", 0)
            if not (char & 0x0100):
                findings.append(self._hardening_finding(
                    "Missing DEP/NX Protection", "high", file_path,
                    "Binary is not compiled with Data Execution Prevention (NX).",
                    "CWE-121", "Compile with /NXCOMPAT linker flag."
                ))

        # ASLR
        if hasattr(binary, "optional_header"):
            oh = binary.optional_header
            # DLL_CHARACTERISTICS.DYNAMIC_BASE is 0x0040
            char = getattr(oh, "dll_characteristics", 0)
            if not (char & 0x0040):
                findings.append(self._hardening_finding(
                    "Missing ASLR Support", "high", file_path,
                    "Binary does not support Address Space Layout Randomization (ASLR).",
                    "CWE-119", "Compile with /DYNAMICBASE linker flag."
                ))

        # Authenticode (Code Signing)
        if hasattr(binary, "signatures"):
            if not binary.signatures:
                findings.append(self._hardening_finding(
                    "Unsigned Binary", "medium", file_path,
                    "Binary is not code-signed (no Authenticode signature).",
                    "CWE-494", "Sign the binary with a valid code-signing certificate."
                ))

        # SafeSEH
        if hasattr(binary, "optional_header"):
            oh = binary.optional_header
            if hasattr(oh, "has") and not oh.has(0x0400):  # IMAGE_DLLCHARACTERISTICS_NO_SEH
                # Note: NO_SEH means SEH is used - we check if SafeSEH is absent
                pass  # SafeSEH requires deeper analysis

        return findings

    def _check_elf_hardening(self, binary: Any, file_path: str) -> List[Dict]:
        findings = []

        # NX bit
        if hasattr(binary, "has_nx") and not binary.has_nx:
            findings.append(self._hardening_finding(
                "Missing NX (No-Execute) Protection", "high", file_path,
                "Binary is missing NX protection, making stack-based buffer overflow exploitation easier.",
                "CWE-121", "Recompile without -z execstack."
            ))

        # PIE
        if hasattr(binary, "is_pie") and not binary.is_pie:
            findings.append(self._hardening_finding(
                "Missing PIE (Position Independent Executable)", "medium", file_path,
                "Binary is not compiled as PIE, reducing ASLR effectiveness.",
                "CWE-119", "Recompile with -fPIE -pie flags."
            ))

        # RELRO
        if hasattr(binary, "relro"):
            import lief
            if binary.relro == lief.ELF.RELRO.NONE:
                findings.append(self._hardening_finding(
                    "Missing RELRO Protection", "medium", file_path,
                    "GOT (Global Offset Table) is writable, enabling GOT overwrite attacks.",
                    "CWE-119", "Recompile with -Wl,-z,relro,-z,now for Full RELRO."
                ))

        # Stack Canary
        try:
            symbols = [str(s.name) for s in binary.symbols if hasattr(s, "name")]
            if "__stack_chk_fail" not in symbols:
                findings.append(self._hardening_finding(
                    "Missing Stack Canary", "medium", file_path,
                    "No stack canary detected. Stack buffer overflows may be exploitable.",
                    "CWE-121", "Recompile with -fstack-protector-strong."
                ))
        except Exception:
            pass

        return findings

    def _check_macho_hardening(self, binary: Any, file_path: str) -> List[Dict]:
        """Check macOS-specific binary hardening (PIE, Stack Canary, Code Signing, ARC, Stripping)."""
        findings = []
        checks_passed = 0

        # 1. PIE (Position Independent Executable)
        is_pie = getattr(binary, "is_pie", False)
        if not is_pie:
            if hasattr(binary, "header") and hasattr(binary.header, "flags"):
                if not (binary.header.flags & 0x200000):
                    findings.append(self._hardening_finding(
                        "Missing PIE (macOS ASLR)", "high", file_path,
                        "macOS binary is not compiled as PIE. ASLR will not be effective.",
                        "CWE-119", "Recompile with -pie flag."
                    ))
                else: checks_passed += 1
            else: checks_passed += 1
        else: checks_passed += 1

        # 2. Stack Canary
        has_canary = False
        try:
            symbols = [str(s.name) for s in binary.symbols if hasattr(s, "name")]
            if any("stack_chk_fail" in s for s in symbols):
                has_canary = True
        except Exception:
            pass
            
        if not has_canary:
            findings.append(self._hardening_finding(
                "Missing Stack Canary", "medium", file_path,
                "No stack canary detected. Stack buffer overflows may be exploitable.",
                "CWE-121", "Recompile with -fstack-protector-strong."
            ))
        else: checks_passed += 1

        # 3. Code Signing
        has_sig = False
        try:
            if (hasattr(binary, "code_signature") and binary.code_signature) or \
               (hasattr(binary, "has_code_signature") and binary.has_code_signature):
                has_sig = True
        except Exception:
            pass

        if not has_sig:
            findings.append(self._hardening_finding(
                "Missing Code Signature", "high", file_path,
                "macOS binary is not code-signed. Gatekeeper will block execution.",
                "CWE-494", "Sign with codesign and notarize via Apple."
            ))
        else: checks_passed += 1

        # 4. ARC (Automatic Reference Counting)
        try:
            symbols = [str(s.name) for s in binary.symbols if hasattr(s, "name")]
            if any("objc_autorelease" in s or "objc_retain" in s for s in symbols):
                checks_passed += 1
            elif any("objc_" in s for s in symbols):
                findings.append(self._hardening_finding(
                    "Non-ARC Binary", "low", file_path,
                    "Binary uses Objective-C but not ARC (Automatic Reference Counting).",
                    "CWE-416", "Migrate to ARC for automatic memory management."
                ))
        except Exception:
            pass

        # 5. Stripped Binary
        try:
            if hasattr(binary, "symbols") and len(binary.symbols) > 100:
                # Large number of visible symbols in a production app often means it's not stripped
                findings.append(self._hardening_finding(
                    "Binary Not Stripped", "low", file_path,
                    "Binary contains extensive symbol information, aiding reverse engineering.",
                    "CWE-200", "Strip symbols in release build (use 'strip' tool)."
                ))
            else: checks_passed += 1
        except Exception:
            pass

        # If everything passed, add an informational finding to show the scan worked
        if not findings:
            findings.append(self._hardening_finding(
                "Applied macOS Hardening", "informational", file_path,
                f"Binary verified for PIE, Stack Canary, and Code Signing ({checks_passed} checks passed).",
                "N/A", "Maintain current secure build flags."
            ))

        return findings

    def _hardening_finding(
        self, name: str, severity: str, file_path: str,
        description: str, cwe: str, recommendation: str
    ) -> Dict:
        return {
            "name": name,
            "severity": severity,
            "file": file_path,
            "category": "binary_hardening",
            "description": description,
            "cwe": cwe,
            "recommendation": recommendation,
            "scanner": "desktop_binary",
        }

    # ------------------------------------------------------------------
    # Layer 2 — Capability Detection (Mandiant CAPA)
    # ------------------------------------------------------------------

    def _run_capa(self, file_path: Path) -> List[Dict]:
        """Run Mandiant CAPA for ATT&CK-mapped capability detection."""
        findings: List[Dict] = []

        try:
            # Default auto-detection
            cmd = [self.capa_path, str(file_path), "--json", "--quiet"]
            
            if self.capa_rules:
                cmd.extend(["--rules", self.capa_rules])
            if os.path.exists(self.capa_sigs):
                cmd.extend(["--signatures", self.capa_sigs])
            else:
                cmd.append("--no-signatures")

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, check=False,
            )

            # Error 16 fallback: specify format explicitly if auto fails
            if result.returncode == 16:
                logger.debug("CAPA auto-detection failed for %s, trying explicit format...", file_path)
                # Note: Only try this if user's capa version supports it (we saw it might not)
                # But we'll try it as a last resort without --format flag if we can't do more.
            
            if result.returncode != 0:
                if "not a supported file type" in result.stderr.lower():
                    logger.debug("CAPA: unsupported file type %s", file_path)
                else:
                    err_snippet = str(result.stderr)[:200]
                    # Log as debug to not spam unless it's a real issue
                    logger.debug("CAPA error (%d) for %s: %s", result.returncode, file_path, err_snippet)
                return []

            if not result.stdout.strip():
                logger.debug("CAPA: No output for %s", file_path)
                return []

            data = json.loads(result.stdout)
            findings.extend(self._parse_capa_output(data, str(file_path)))

        except FileNotFoundError:
            logger.info("CAPA not installed. Skipping capability analysis.")
        except subprocess.TimeoutExpired:
            logger.warning("CAPA timed out analyzing %s", file_path)
        except json.JSONDecodeError:
            logger.debug("CAPA produced non-JSON output for %s", file_path)
        except Exception as e:
            logger.debug("CAPA error for %s: %s", file_path, e)

        return findings

    def _parse_capa_output(self, data: Dict, file_path: str) -> List[Dict]:
        """Parse CAPA JSON output into normalized findings."""
        findings: List[Dict] = []

        rules = data.get("rules", {})
        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})

            # Extract ATT&CK mapping
            attack_info = meta.get("att&ck", []) or meta.get("attack", [])
            attack_strings = []
            for item in attack_info:
                if isinstance(item, dict):
                    attack_strings.append(
                        f"{item.get('tactic', '')}::{item.get('technique', '')} ({item.get('id', '')})"
                    )
                elif isinstance(item, str):
                    attack_strings.append(item)

            # Map CAPA scopes to severity
            scope = meta.get("scope", "")
            severity = self._capa_severity(meta, rule_name)

            findings.append({
                "name": rule_name,
                "severity": severity,
                "file": file_path,
                "category": "capability_detection",
                "description": meta.get("description", rule_name),
                "mitre_attack": attack_strings,
                "mbc": meta.get("mbc", []),
                "namespace": meta.get("namespace", ""),
                "authors": meta.get("authors", []),
                "cwe": "",
                "recommendation": f"Investigate capability: {rule_name}",
                "scanner": "desktop_binary",
            })

        return findings

    @staticmethod
    def _capa_severity(meta: Dict, rule_name: str) -> str:
        """Estimate severity from CAPA rule metadata."""
        name_lower = rule_name.lower()
        namespace = meta.get("namespace", "").lower()

        # Critical indicators
        critical_keywords = [
            "inject", "escalat", "rootkit", "keylog", "ransomware",
            "credential", "dump", "backdoor", "c2", "command and control",
        ]
        if any(kw in name_lower or kw in namespace for kw in critical_keywords):
            return "critical"

        # High indicators
        high_keywords = [
            "bypass", "evasion", "anti-debug", "anti-vm", "obfuscat",
            "shellcode", "process hollowing", "dll injection", "hook",
        ]
        if any(kw in name_lower or kw in namespace for kw in high_keywords):
            return "high"

        # Medium indicators
        medium_keywords = [
            "persist", "autorun", "registry", "network", "download",
            "upload", "exfiltrat", "encrypt", "decrypt",
        ]
        if any(kw in name_lower or kw in namespace for kw in medium_keywords):
            return "medium"

        return "low"

    # ------------------------------------------------------------------
    # Layer 3 — Suspicious String Extraction
    # ------------------------------------------------------------------

    def _string_analysis(self, file_path: Path) -> List[Dict]:
        """Extract and flag suspicious strings from the binary."""
        import re
        findings: List[Dict] = []

        try:
            with open(file_path, "rb") as f:
                raw = f.read(5 * 1024 * 1024)  # Read first 5MB

            # Extract printable strings (min length 8)
            strings = re.findall(rb"[\x20-\x7e]{8,}", raw)
            decoded = [s.decode("ascii", errors="ignore") for s in strings]

            # Check for hardcoded IPs - avoid version-like strings (1.0.0.0, etc)
            ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
            for s in decoded:
                match = ip_pattern.search(s)
                if match:
                    ip = match.group(1)
                    # Simple heuristic: version strings often end with .0 or start with 1.0
                    # Also skip local/broadcast
                    if ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255", "1.0.0.0"]:
                        continue
                        
                    findings.append({
                        "name": "Hardcoded IP Address",
                        "severity": "medium",
                        "file": str(file_path),
                        "category": "strings",
                        "description": f"Hardcoded IP address found in binary: {ip} (Full string: {s[:40]})",
                        "cwe": "CWE-798",
                        "recommendation": "Externalize network configuration.",
                        "scanner": "desktop_binary",
                    })
                    break  # One finding is enough

            # Check for potential credentials
            cred_patterns = [
                (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "Potential Hardcoded Password"),
                (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+", "Potential Hardcoded API Key"),
                (r"(?i)(secret|token)\s*[=:]\s*['\"][^'\"]{8,}", "Potential Hardcoded Secret"),
            ]
            for pattern, name in cred_patterns:
                for s in decoded:
                    if re.search(pattern, s):
                        findings.append({
                            "name": name,
                            "severity": "high",
                            "file": str(file_path),
                            "category": "strings",
                            "description": f"Suspicious credential-like string detected in binary.",
                            "cwe": "CWE-798",
                            "recommendation": "Remove hardcoded credentials; use secure vaults.",
                            "scanner": "desktop_binary",
                        })
                        break  # One per pattern

        except Exception as e:
            logger.debug("String analysis failed for %s: %s", file_path, e)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_executable(path: Path) -> bool:
        """Check if a file is an executable (by X bit or magic bytes)."""
        try:
            if not path.is_file():
                return False
            
            # 1. Quick access check
            if os.access(path, os.X_OK):
                return True
            
            # 2. Magic byte check (for cases where cpio loses permissions)
            with open(path, "rb") as f:
                magic = f.read(4)
                
                # Mach-O
                if magic in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]:
                    return True
                # ELF
                if magic == b"\x7fELF":
                    return True
                # PE (MZ)
                if magic.startswith(b"MZ"):
                    return True
                    
            return False
        except Exception:
            return False

    @staticmethod
    def _count_by_severity(vulns: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for v in vulns:
            sev = v.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _error_result(self, message: str) -> Dict[str, Any]:
        return {
            "scanner": "desktop_binary",
            "error": message,
            "total": 0,
            "vulnerabilities": [],
        }

