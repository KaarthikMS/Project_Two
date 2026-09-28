"""
HTML Report Generator - Creates premium, interactive security dashboards.
Uses Vanilla CSS and JS for ultra-lightweight, zero-dependency visual excellence.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

class HtmlReportGenerator:
    """
    Generates high-fidelity HTML security assessment reports mirroring the active dashboard.
    """

    def generate(self, summary: Dict[str, Any], results_list: List[Dict[str, Any]], ai_analysis: str | None = None) -> str:
        """
        Produce a self-contained HTML report with CSS and minimal interactivity.
        """
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        severity_counts = summary.get("severity_counts", {})
        
        # Raw JSON
        raw_telemetry_json = json.dumps(results_list, indent=2)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Two | Security Intelligence</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {{
            --bg-base: #030712;
            --bg-surface: rgba(17, 24, 39, 0.7);
            --bg-surface-hover: rgba(31, 41, 55, 0.8);
            --border-light: rgba(255, 255, 255, 0.08);
            
            --primary: #38bdf8;
            --secondary: #8b5cf6;
            
            --accent-success: #10b981;
            --accent-warning: #f59e0b;
            --accent-danger: #ef4444;

            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #f59e0b;
            --color-low: #38bdf8;
            --color-info: #9ca3af;

            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            
            --font-sans: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}

        * {{ box-sizing: border-box; transition: background-color 0.2s, border-color 0.2s; }}

        body {{
            font-family: var(--font-sans);
            background-color: var(--bg-base);
            color: var(--text-main);
            margin: 0; padding: 0;
            line-height: 1.6;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 50%, rgba(56, 189, 248, 0.08), transparent 25%),
                radial-gradient(circle at 85% 30%, rgba(139, 92, 246, 0.08), transparent 25%);
            background-attachment: fixed;
            padding-bottom: 60px;
        }}

        ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-base); }}
        ::-webkit-scrollbar-thumb {{ background: #374151; border-radius: 4px; }}

        .navbar {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 1rem 3rem;
            background: rgba(3, 7, 18, 0.6);
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border-light);
            position: sticky; top: 0; z-index: 100;
        }}

        .brand {{
            font-size: 1.5rem; font-weight: 700;
            display: flex; align-items: center; gap: 0.75rem;
            letter-spacing: 0.02em;
            background: linear-gradient(135deg, #38bdf8, #8b5cf6);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}

        .brand svg {{ width: 28px; height: 28px; }}

        .scan-meta {{
            display: flex; align-items: center; gap: 1rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .active-scan-header {{
            background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.1);
            border-radius: 16px; padding: 1.25rem 2rem; margin-bottom: 2rem;
            display: flex; justify-content: space-between; align-items: center;
        }}

        .status-badge {{
            padding: 0.4rem 1rem; border-radius: 99px;
            font-weight: 600; text-transform: uppercase; font-size: 0.7rem;
            letter-spacing: 0.05em; display: flex; align-items: center; gap: 0.5rem;
        }}

        .status-secure {{ background: rgba(16, 185, 129, 0.1); color: var(--accent-success); border: 1px solid rgba(16, 185, 129, 0.2); }}
        .status-risk {{ background: rgba(239, 68, 68, 0.1); color: var(--accent-danger); border: 1px solid rgba(239, 68, 68, 0.2); }}

        .main-container {{
            max-width: 1400px; margin: 2rem auto; padding: 0 2rem;
            animation: fadeIn 0.4s ease-out forwards;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        .bento-grid {{
            display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.5rem;
        }}

        .glass-card {{
            background: var(--bg-surface); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-light); border-radius: 20px;
            padding: 1.5rem; position: relative; overflow: hidden;
        }}

        .glass-card:hover {{ border-color: rgba(255,255,255,0.15); box-shadow: 0 8px 32px rgba(0,0,0,0.4); }}

        .col-span-3 {{ grid-column: span 3; }}
        .col-span-4 {{ grid-column: span 4; }}
        .col-span-8 {{ grid-column: span 8; }}
        .col-span-12 {{ grid-column: span 12; }}

        .card-header {{
            display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;
            color: var(--text-muted); font-size: 0.75rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.08em;
        }}

        .card-header span {{ display: flex; align-items: center; gap: 0.5rem; }}
        .card-header svg {{ width: 16px; height: 16px; color: var(--primary); }}

        .stat-value {{ font-size: 3rem; font-weight: 700; color: var(--text-main); line-height: 1; }}

        /* Markdown Styles */
        .markdown-container {{ font-size: 1rem; color: #d1d5db; }}
        .markdown-container h1 {{ font-size: 1.5rem; color: var(--primary); border-bottom: 1px solid var(--border-light); padding-bottom: 0.5rem; margin-top: 1.5rem; margin-bottom: 1rem; }}
        .markdown-container h2 {{ font-size: 1.25rem; color: #fff; margin-top: 1.5rem; margin-bottom: 1rem; }}
        .markdown-container h3 {{ font-size: 1.1rem; color: #f3f4f6; margin-top: 1.25rem; margin-bottom: 0.75rem; }}
        .markdown-container th, .markdown-container td {{ border: 1px solid var(--border-light); padding: 8px 16px; }}
        .markdown-container th {{ background: rgba(255,255,255,0.05); text-align: left; }}
        .markdown-container table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
        .markdown-container code {{ background: rgba(56, 189, 248, 0.1); color: var(--primary); padding: 0.1rem 0.3rem; border-radius: 4px; font-family: var(--font-mono); }}
        .markdown-container pre {{ background: #000; padding: 1rem; border-radius: 8px; overflow-x: auto; border: 1px solid var(--border-light); }}
        .markdown-container p {{ margin-bottom: 1rem; }}
        .markdown-container ul, .markdown-container ol {{ margin-bottom: 1rem; padding-left: 2rem; }}
        .markdown-container blockquote {{ border-left: 4px solid var(--primary); margin: 0 0 1rem 0; padding-left: 1rem; color: var(--text-muted); font-style: italic; background: rgba(56, 189, 248, 0.05); padding: 1rem; border-radius: 0 4px 4px 0; }}
        
        /* Interactive Findings */
        .finding-card {{
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border-light);
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .finding-card:hover {{ border-color: rgba(255,255,255,0.15); }}
        
        .finding-header {{
            padding: 16px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .finding-meta {{ display: flex; align-items: center; gap: 15px; }}
        .severity-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
        
        .finding-details {{
            display: none;
            padding: 0 20px 20px;
            background: rgba(0,0,0,0.2);
            border-top: 1px solid var(--border-light);
            font-size: 0.9rem;
        }}
        .finding-card.active .finding-details {{ display: block; }}
        
        .finding-info-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 12px;
            margin-top: 16px;
        }}
        .info-label {{ color: var(--text-muted); font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        
        .filter-buttons {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .filter-btn {{
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-light);
            color: var(--text-muted);
            padding: 6px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.85rem;
            font-family: var(--font-sans);
            font-weight: 500;
        }}
        .filter-btn:hover {{ background: rgba(255,255,255,0.1); color: var(--text-main); }}
        .filter-btn.active {{ background: rgba(56, 189, 248, 0.15); border-color: var(--primary); color: var(--primary); }}

        .terminal-block {{ 
            background: #000; border-radius: 12px; padding: 1.5rem; 
            font-family: var(--font-mono); font-size: 0.85rem; color: #8bb1ff; 
            max-height: 400px; overflow: auto; white-space: pre;
            border: 1px solid var(--border-light);
            line-height: 1.5;
        }}
        
        .badge-small {{
            background: rgba(255,255,255,0.1);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: var(--font-mono);
        }}
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="brand">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Project<span style="font-weight: 300;">Two</span>
        </div>
        <div class="scan-meta">
            Static Report generated at {timestamp}
        </div>
    </nav>

    <div class="main-container">
        <!-- Prominent Run Metadata -->
        <div class="active-scan-header">
            <div>
                <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Security Scan Report</div>
                <div style="font-size: 1.25rem; font-weight: 700; font-family: var(--font-mono); color: var(--primary);">STATIC-REPORT</div>
            </div>
            <div class="status-badge { 'status-secure' if summary.get('quality_gate_passed', True) else 'status-risk' }">
                { summary.get('overall_status', 'REPORT GENERATED') }
            </div>
        </div>

        <div class="bento-grid">
            <div class="glass-card col-span-3">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Initial Findings</span></div>
                <div class="stat-value">{ summary.get('total_vulnerabilities', 0) }</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Total raw security signals</div>
            </div>

            <div class="glass-card col-span-3">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Critical</span></div>
                <div class="stat-value" style="color: var(--color-critical);">{ severity_counts.get('critical', 0) }</div>
            </div>
            
            <div class="glass-card col-span-3">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> High</span></div>
                <div class="stat-value" style="color: var(--color-high);">{ severity_counts.get('high', 0) }</div>
            </div>

            <div class="glass-card col-span-3">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Quality Gate</span></div>
                <div class="stat-value" style="color: { 'var(--accent-success)' if summary.get('quality_gate_passed', True) else 'var(--accent-danger)' }; font-size: 2rem; margin-top: 10px;">
                    { 'PASSED' if summary.get('quality_gate_passed', True) else 'FAILED' }
                </div>
            </div>

            { self._render_ai_section(ai_analysis) if ai_analysis else "" }

            <div class="glass-card col-span-12">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg> Detailed Correlated Findings</span></div>
                
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" onclick="filterFindings('critical')" style="border-left: 3px solid var(--color-critical)">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('high')" style="border-left: 3px solid var(--color-high)">High</button>
                    <button class="filter-btn" onclick="filterFindings('medium')" style="border-left: 3px solid var(--color-medium)">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('low')" style="border-left: 3px solid var(--color-low)">Low</button>
                </div>

                <div id="findings-container">
                    { self._render_findings(results_list) }
                </div>
            </div>

            <div class="glass-card col-span-12">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg> Raw Findings Telemetry (Structured JSON)</span></div>
                <pre class="terminal-block">{raw_telemetry_json}</pre>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {{
            // Render Markdown
            const rawContentDiv = document.getElementById('ai-raw-content');
            if (rawContentDiv) {{
                const rawContent = rawContentDiv.textContent;
                document.getElementById('ai-rendered-content').innerHTML = marked.parse(rawContent);
            }}
        }});

        function toggleFinding(el) {{
            el.parentElement.classList.toggle('active');
        }}

        function filterFindings(severity) {{
            const cards = document.querySelectorAll('.finding-card');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {{
                if (severity === 'all' || card.dataset.severity === severity) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        return html

    def _render_ai_section(self, content: str) -> str:
        # We store the raw markdown in a hidden div, let marked.js render it into ai-rendered-content
        import html # to escape any weird content
        escaped_content = html.escape(content)
        return f"""
            <div class="glass-card col-span-12">
                <div class="card-header"><span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2h-1.5v2.5h-3V8.5H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h6z"/><path d="M4 14a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2z"/><path d="M14 14a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2v-2z"/></svg> AI Security Synthesis (Claude 3.5 Bedrock)</span></div>
                <div id="ai-raw-content" style="display:none;">{escaped_content}</div>
                <div id="ai-rendered-content" class="markdown-container"></div>
            </div>
        """

    def _render_findings(self, results_list: List[Dict[str, Any]]) -> str:
        all_correlated = []
        for r in results_list:
            all_correlated.extend(r.get("correlated_findings", []))

        if not all_correlated:
            return "<div class='empty-state' style='padding: 3rem; text-align: center; color: var(--text-muted); border: 1px dashed var(--border-light); border-radius: 12px;'>No security vulnerabilities detected.</div>"

        html_snippets = []
        for i, finding in enumerate(all_correlated):
            sev = finding.get("severity", "low").lower()
            color = {
                "critical": "var(--color-critical)",
                "high": "var(--color-high)",
                "medium": "var(--color-medium)",
                "low": "var(--color-low)",
                "informational": "var(--color-info)"
            }.get(sev, "var(--color-info)")

            snippet = f"""
            <div class="finding-card" data-severity="{sev}">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <div class="finding-meta">
                        <div class="severity-dot" style="background: {color}; box-shadow: 0 0 8px {color};"></div>
                        <span style="font-weight: 600; font-size: 0.95rem; color: #fff;">{ finding.get('name', 'Unknown') }</span>
                    </div>
                    <div style="display: flex; gap: 12px; align-items: center;">
                        <span class="badge-small" style="color: {color}; border: 1px solid {color}40;">{ sev.upper() }</span>
                        <span style="color: var(--text-muted); font-size: 0.8rem;">#{i+1}</span>
                    </div>
                </div>
                <div class="finding-details">
                    <div class="finding-info-grid">
                        <div class="info-label">Description</div>
                        <div style="color: #d1d5db;">{ finding.get('description', 'N/A') }</div>
                        
                        <div class="info-label">Detection Source</div>
                        <div><span class="badge-small">{ ', '.join(finding.get('scanners', [])) }</span></div>
                        
                        <div class="info-label">Matched At</div>
                        <div><code style="background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono);">{ finding.get('matched_at', 'N/A') }</code></div>
                        
                        <div class="info-label">CWE</div>
                        <div>{ finding.get('cwe', 'N/A') }</div>
                        
                        <div class="info-label">Remediation</div>
                        <div style="color: var(--accent-success); font-weight: 500;">{ finding.get('remediation', 'N/A') }</div>
                    </div>
                </div>
            </div>
            """
            html_snippets.append(snippet)
        
        return "\\n".join(html_snippets)
