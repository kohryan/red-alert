# REA tool reference

REA (<https://github.com/morluto/rea>, MIT) exposes one MCP surface across binaries, applications
and runtime behaviour, with a shared evidence contract. Use it when it is connected; it removes
most of the tool-plumbing work described in `target-routing.md`.

The method in this skill is derived from REA's own agent skill. This file is the concrete mapping.

## 1. Connecting

```bash
# one-off CLI (no MCP registration needed for static JS analysis)
npx -y rea-agents@latest analyze-javascript-application /abs/path/to/app --json

# MCP registration for a client that supports local stdio servers
npx -y rea-agents@latest setup --client <client> --dry-run --json   # read-only plan
npx -y rea-agents@latest setup --client <client> --yes              # apply approved scope
npx -y rea-agents@latest doctor --client <client> --json            # diagnose
```

In this repo, `kilo.json` already declares the server as disabled:

```jsonc
"mcp": { "rea": { "type": "local", "command": ["npx", "-y", "rea-agents@latest", "mcp"], "enabled": false } }
```

Enable it by flipping `enabled` to `true`, or use the CLI directly. REA needs Node.js 22.x
(≥22.19), 24.x (≥24.11) or 26+.

**REA never installs engines.** Hopper, Ghidra, IDA, JADX, JDK, Java, Binwalk, Unblob, mitmproxy
and tshark are bring-your-own. If a provider is missing, that technique is `unknown` — continue
with what works.

## 2. The REA evidence contract

Every REA tool returns an **Evidence record**:

| Field | Meaning |
| --- | --- |
| `evidence_id` | Stable handle. Cite it. Use it to page the same result without re-running the producer. |
| `normalized_result` | The operation data |
| `limitations` | Ordered list of what the provider could not do |
| `coverage` | What was examined (complete / partial with counts) |
| `parent_evidence_id` | Handle for the complete retained result when a view is returned |

Rules REA's own docs state, and that this repo inherits:

- A `summary` detail request **retains the complete source** and returns a small view. The parent
  ID is how you get the rest.
- **Never re-run a producer to get a different rendering.** Use `inspect_analysis_view` with the
  parent ID.
- `resource_constraint` with `details.resource: "transport"` means the reply was too big for the
  transport, not that the analysis failed. Page it or export a bundle.
- A client-side truncation is a **display** limitation. Treat the visible part as a preview.
- Absence of a record in a partial source is **not** absence in the artifact.
- Provider capability lists describe *possible* providers; session capabilities describe the
  *current* route. Do not mix them.

## 3. Phase → REA tool map

| Skill phase | REA tools |
| --- | --- |
| Intake | `open_binary`, `inspect_artifact`, `open_bundle_resources` |
| Format detection | `inspect_binary_layout` (ELF), `inspect_macho`, `inspect_pe_resources`, `inspect_managed_artifact` |
| Build metadata | `inspect_go_binary`, `inspect_rust_binary`, `inspect_il2cpp_metadata` |
| Container inventory | `inspect_artifact`, `inspect_desktop_application`, `project_apple_application_graph` |
| JS / Electron graph | `analyze_javascript_application`, `recover_javascript_sources` |
| Source recovery | `recover_javascript_sources`, `inspect_analysis_view` (kind `javascript`) |
| Feature trace | `trace_application_feature`, `inspect_analysis_view` (kind `item`) |
| Android | `inspect_android_package`, `inspect_android_resources`, `list_android_devices` |
| Decompilation | `analyze_function`, `procedure_pseudo_code`, `list_procedures`, `search_strings` |
| Cross-references | `xrefs`, `list_callers`, `list_callees` |
| Bytes / tables | `read_bytes`, `address_to_file_offset`, `list_segments` |
| Annotations | `annotate_native_function`, `set_address_name` |
| Runtime (browser) | `list_browser_targets`, `inspect_web_page`, `observe_web_session`, `capture_browser_scenario` |
| Runtime (Electron) | `list_electron_targets`, `inspect_electron_fuses` |
| Network | `inspect_web_network_capture`, `inspect_pcap_capture`, `inspect_packet_capture`, `inspect_packet_fields` |
| Firmware | `inspect_firmware_regions`, `extract_firmware` |
| Comparison | `compare_artifacts`, `compare_functions`, `compare_bundles`, `find_changed_behavior`, `compare_application_versions` |
| Reconstruction | `build_call_path`, `verify_reconstruction`, `reconstruct_coverage` (see docs) |
| Unknown tracking | `record_unknown`, `update_unknown` |
| Paging | `inspect_analysis_view` (kind-specific facets), `get_evidence_bundle`, `export_evidence_bundle` |
| Session | `binary_session`, `close_binary` |

Full tool catalogue and schemas: `docs/mcp-contracts.md` in the REA repository; the connected
server's `tools/list` is canonical.

## 4. REA idioms worth copying into any workflow

**Summary-first with a retained parent.**

```text
analyze_javascript_application(dir, detail: "summary")
  → view of counts + parent_evidence_id
inspect_analysis_view(source: {kind: "retained-evidence", evidence_id: <parent>},
                      view: {kind: "page", collection: "modules", offset: 0, limit: 16})
  → node ids and roles; pick the node you need
inspect_analysis_view(source: …, view: {kind: "item", collection: "modules",
                                         selector: {node_id: "<node_id>"}})
  → that module's observations
```

**Native value flow without re-decompiling.**

```text
analyze_function(address)
inspect_analysis_view(source: {kind: "retained-evidence", evidence_id: <fn evidence>},
                      view: {kind: "native", facet: "value_flow_operations",
                             offset: 0, limit: 32})
```

**Tracking unknowns in the session**, so an open question cannot be lost between passes:

```text
record_unknown(question: "does update_tick run at startup?", supporting_evidence: [EV-…])
update_unknown(unknown_id: <id>, revision: <rev>, resolution_evidence: [EV-…])
```

**Export before closing.** Closing a session clears retained references. If the evidence must
survive the session, export a bundle (`export_evidence_bundle`) or keep the complete inline
record.

## 5. When REA is not connected

Use the local ladder:

```bash
file -b <f>; shasum -a 256 <f>; xxd -l 64 <f>
strings -a -n 4 <f> | head -200
otool -l <f> | head -80          # macOS
readelf -a <f> | head -120        # Linux
objdump -d <f> | head -200        # fallback disassembly
python3 -m json.tool             # structured formats
```

Deep analysis without REA means driving Hopper/Ghidra/IDA/rizin yourself — the method is the same,
only the plumbing differs. Preserve the evidence contract yourself: assign IDs, record locators,
and record coverage, exactly as `epistemics-and-evidence.md` requires.

## 6. Attribution

REA is MIT-licensed, Copyright (c) morluto. This repository re-expresses its methodology for
Kilo-based agentic work and credits it in `LICENSE` and `docs/tooling/rea-integration.md`.
