# ShieldPrompt Dashboard - Terminal Startup Guide

## Quick Start

### 1. Verify Environment
```bash
cd /Users/isaganijulian/Shield-Prompt

# Check Python version (must be 3.12+)
python --version

# Verify virtual environment
source .venv/bin/activate

# Check dependencies
pip list | grep streamlit
```

### 2. Run the Dashboard

**Standard mode:**
```bash
streamlit run src/dashboard/app.py
```

**With automatic browser launch:**
```bash
streamlit run src/dashboard/app.py --logger.level=info
```

**Development mode (auto-reload on file changes):**
```bash
streamlit run src/dashboard/app.py --logger.level=debug --client.showErrorDetails=true
```

### 3. Access the Dashboard
- **Local URL**: `http://localhost:8501`
- **Default mode**: 🛡️ Playground
- **Browser**: Opens automatically (or manually navigate above)

---

## Navigation Guide

### **Sidebar Controls**
```
⚙️ Configuration
├─ Select Mode: [🛡️ Playground, 🎛️ Detection, 📊 Evaluation, 🔍 Threat Intel]
├─ Detection Threshold: 0.0 - 1.0 (default 0.85)
├─ Enable Auto-Remediation: ☑ (enabled)
├─ 🔄 Refresh Metrics: Updates KPI cards
└─ 🔄 Inject Mock Traffic Feed (expandable)
   └─ Inject 8 Mock Scan Records: Pre-populate audit trail
```

### **Playground Mode** (Default)
```
🎯 Live Ingress Playground & Visualizer

Left Panel (📥 Ingress Input Panel):
├─ Template Selector: 6 pre-built attack/safe payloads
├─ Custom Payload Text Area: 250px for JSON or plain text
├─ Byte Counter: Real-time payload size
└─ 🚀 Simulate Ingress Scan: Run full pipeline

Right Panel (🔍 Pipeline Analysis Trace):
├─ Decision Banner: Color-coded verdict + confidence
├─ ✅ Step 1: Structural Check
│  ├─ 🟢 Structural Fast Path (metrics + samples)
│  └─ 🟠 Scannable Active Path (metrics + samples)
├─ ⚡ Step 2: Tier 1 Lexical Detection
│  ├─ 🚨 CRITICAL THREAT alerts (if triggered)
│  └─ Color-coded threat levels
├─ 🔄 Step 3: Normalization & Preprocessing
│  ├─ Before/After code blocks
│  ├─ Detected encodings (Base64, Hex, URL)
│  └─ Applied transformations
├─ ✔️ Step 4: Final Verdict
│  ├─ Decision + Confidence
│  ├─ Auto-remediation status
│  └─ 📜 Full Audit Trail (expandable)
└─ 📋 Forensic Audit Trail (at bottom)
   ├─ Interactive dataframe with session history
   ├─ Conditional highlighting (red for BLOCK)
   ├─ Summary metrics (Total Scans, Blocked, Avg Latency, Threats)
   └─ Export options (CSV, JSON)
```

### **Detection Mode**
```
🎛️ Detection
├─ Header: 🛡️ ShieldPrompt Security Console + ● System Active
├─ Metrics Row: Average Latency, Total Scanned, Threats Blocked, Compute Savings
├─ Quick Detection Tool
│  ├─ Text area for single payload
│  └─ 🔍 Analyze button
└─ 📋 Forensic Audit Trail (at bottom)
```

---

## Usage Workflows

### **Workflow 1: Test Pre-built Templates**

1. Keep Playground mode (default)
2. Use template dropdown to select:
   - "Safe Query" → ALLOW verdict expected
   - "Simple Injection" → BLOCK/ESCALATE verdict expected
   - "Obfuscated Unicode" → QUARANTINE verdict expected
   - "Base64 Encoded" → REMEDIATE verdict expected
   - "JSON MCP Payload" → Mixed structural/scannable
   - "Messy JSON" → Realistic enterprise envelope
3. Click 🚀 Simulate Ingress Scan
4. Observe step-by-step trace on right
5. Scroll down to see entry in Forensic Audit Trail

### **Workflow 2: Inject Mock Traffic (Professional Dashboard)**

1. Open sidebar: 🔄 Inject Mock Traffic Feed
2. Click "Inject 8 Mock Scan Records"
3. See success toast: ✅ Mock traffic injected!
4. Scroll to bottom → Forensic Audit Trail now populated
5. Table shows 8 historic entries with varying:
   - Verdicts (ALLOW, BLOCK, QUARANTINE, REMEDIATE)
   - Latencies (5-18ms)
   - Payload types
   - Threat counts
6. Rows highlighted in red for BLOCK verdicts
7. Download as CSV or JSON for external analysis

### **Workflow 3: Custom Payload Testing**

1. Clear template dropdown or paste JSON
2. Enter custom payload in text area
3. Click 🚀 Simulate Ingress Scan
4. Wait for analysis (spinner shows progress)
5. Review step-by-step trace:
   - Step 1: Field classification (how many routed to scanning?)
   - Step 2: Tier 1 early-exit (regex signatures triggered?)
   - Step 3: Normalization (encodings detected? transformations applied?)
   - Step 4: Verdict (final decision with evidence)
6. New entry auto-logged to Forensic Audit Trail

### **Workflow 4: Forensic Audit Analysis**

1. After several scans, scroll to bottom
2. View Forensic Audit Trail table:
   - **Timestamp**: When scan was run
   - **Ingress Payload Type**: Auto-detected (Plain Text, JSON, MCP, Base64, Unicode Obfuscated)
   - **Targeted Field**: JSON path of primary threat
   - **Final Verdict**: ALLOW/BLOCK/QUARANTINE/REMEDIATE/ESCALATE
   - **Latency (ms)**: Processing time
3. Row styling:
   - Red background: BLOCK verdicts
   - Yellow background: QUARANTINE verdicts
   - Blue background: REMEDIATE verdicts
   - Normal: ALLOW/ESCALATE verdicts
4. Summary metrics above table:
   - Total Scans: Count of all entries
   - Blocked: Count of BLOCK verdicts
   - Avg Latency: Mean processing time
   - Threats Detected: Sum of threat_count across all
5. Export options:
   - 📥 Export as CSV: Open in Excel/Google Sheets
   - 📥 Export as JSON: Load into analysis tools
   - 🗑️ Clear History: Reset audit trail

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` or `Cmd+R` | Refresh dashboard |
| `Ctrl+F` or `Cmd+F` | Search in browser (text area, table) |

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'streamlit'"
**Solution:**
```bash
pip install streamlit pandas
source .venv/bin/activate
```

### Issue: "Dashboard crashes on invalid JSON"
**Solution:** 
- Dashboard has graceful error handling
- Invalid JSON auto-treated as plain text
- Error message displayed above pipeline trace
- Audit trail still logs the scan

### Issue: "Mock traffic not appearing"
**Solution:**
- Click "Inject 8 Mock Scan Records" in sidebar
- Wait 2-3 seconds for toast notification
- Scroll down to Forensic Audit Trail table

### Issue: "Audit trail is empty"
**Solution:**
- Either use Playground to run scans, or
- Inject mock traffic via sidebar, or
- Both (mixed audit entries allowed)

---

## Integration with Core Modules

All dashboard components seamlessly integrate with ShieldPrompt core:

✅ **PayloadParser** (`core/payload_parser.py`)
- Used in Playground for field classification
- Detects MCP envelopes, JSON, plain text

✅ **ShieldDetector** (`core/shield.py`)
- Tier 1-3 detection displayed in pipeline trace
- Evidence shown in step-by-step visualization

✅ **DualGateRouter** (`core/router.py`)
- Main orchestration engine for all scans
- Routing decision synthesized from field detections

✅ **InputNormalizer** (`core/preprocessor.py`)
- Unicode/encoding normalization shown in Step 3
- Before/After diff displayed in Playground

✅ **SupervisorAgent** (`core/supervisor.py`)
- Auto-remediation results shown in Step 4

✅ **Test Coverage** (116 tests)
- All core modules tested via `tests/evaluate.py`
- Dashboard uses same tested components

---

## Performance Notes

- **First load**: ~2-3 seconds (imports, initializations)
- **Scan latency**: 5-20ms per payload (depends on Tier 1-3 routing)
- **Mock traffic injection**: Instant (pre-computed 8 entries)
- **Audit table scrolling**: 8-100 entries recommended for smooth performance
- **CSV export**: <1 second for typical session (8-50 entries)

---

## Example Session Flow

```
1. Launch dashboard
   $ streamlit run src/dashboard/app.py

2. (Optional) Inject mock traffic
   Sidebar → 🔄 Inject Mock Traffic Feed
   Click "Inject 8 Mock Scan Records"
   ✅ Mock traffic injected! (Toast)

3. Test template
   Select "Simple Injection" from dropdown
   Click 🚀 Simulate Ingress Scan
   Observe: 🚨 CRITICAL THREAT in Step 2 (Tier 1 early-exit)

4. Scroll down
   View Forensic Audit Trail
   See new row: Simple Injection | $.query | BLOCK | 8.3ms (highlighted red)

5. Export results
   Click 📥 Export as CSV
   File: audit_trail_20250526_102030.csv downloaded

6. Test custom payload
   Clear template, paste: "What is 2+2?"
   Click 🚀 Simulate Ingress Scan
   Observe: ✅ ALLOW in Step 4

7. Exit
   Ctrl+C in terminal
   Session data auto-cleared (or export before exit)
```

---

## Reference: Test Coverage

All dashboard features use components with >95% test coverage:

```
tests/test_router.py              → DualGateRouter routing logic
tests/test_payload_parser.py       → Field classification accuracy
tests/test_preprocessor.py         → Normalization correctness
core/shield.py (Tier 1-3 logic)   → Detection signatures
```

Run tests before starting dashboard (optional):
```bash
pytest tests/ -v
streamlit run src/dashboard/app.py
```

---

## Support

For issues or feature requests, check:
- `CLAUDE.md` - System context and constraints
- `docs/ARCHITECTURE.md` - Phase 3 & 4 specifications
- `core/` modules - Implementation details
- `src/dashboard/` - Dashboard-specific code

Happy testing! 🛡️
