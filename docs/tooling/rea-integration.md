# REA integration

This workspace's method is adapted from [REA](https://github.com/morluto/rea) (MIT, © morluto) —
"Reverse engineer anything with agents, from app behavior down to native binaries". REA exposes
one MCP surface across binaries, applications and runtime behaviour, with a shared evidence
contract, and it ships an agent skill that encodes much of the method used here.

This page records the mapping and the attribution.

## What was taken from REA

| REA concept | In this repo |
| --- | --- |
| The evidence contract: stable IDs, `limitations`, `coverage`, `parent_evidence_id` | `docs/methodology/03-evidence-reporting.md`, `scripts/re/ledger.py` |
| The epistemics discipline: observation vs derivation vs inference vs unknown | `docs/methodology/00-principles.md`, `.kilo/skills/reverse-engineer/references/epistemics-and-evidence.md` |
| Summary-first delivery with retained parents | `.kilo/skills/reverse-engineer/SKILL.md` §11 |
| "Do not repeat an identical call; page the retained result" | skill §11, `references/rea-tool-reference.md` |
| Fail-closed integration (scope/authority/side-effect questions before capability) | `docs/methodology/00-principles.md` §5 |
| Provider capability vs session capability vs candidate capability | `references/rea-tool-reference.md` §2 |
| Target routing across ~25 artifact classes | `docs/methodology/02-target-routing.md` |
| Comparison discipline (complete, compatible page sets) | skill §7 |
| Reconstruction obligation ledgers and coverage proof | `references/reconstruction-and-verification.md` |
| Ownership vs validity vs readiness | `docs/methodology/00-principles.md` §7 |
| Performance ordering: tokens → analysis time → CPU/memory | skill §11, principles §8 |

## What is this repo's own

- The **agentic operating surface**: Kilo skills, subagents, and slash commands under `.kilo/`.
- The **safety rails** for running untrusted targets (sandbox, network isolation, no host
  execution) — REA describes its own side effects; this repo makes them a precondition.
- The **defensive security half**: `security/`, `scripts/sec/`, the `red-alert-audit` skill.
- The **tooling that works without REA**: `scripts/re/triage.sh`, `scripts/re/ledger.py`,
  `scripts/sec/*` — pure standard library, no MCP server needed.
- The **plain-language corpus** under `docs/`.

## Using REA from this workspace

The project config already declares the server, disabled:

```jsonc
"mcp": {
  "rea": {
    "type": "local",
    "command": ["npx", "-y", "rea-agents@latest", "mcp"],
    "enabled": false,
    "timeout": 600000
  }
}
```

Enable it, or use the CLI without any registration:

```bash
npx -y rea-agents@latest analyze-javascript-application /abs/path/to/app --json
npx -y rea-agents@latest setup --client codex --dry-run --json   # read-only plan
npx -y rea-agents@latest doctor --client codex --json            # diagnose
```

Requirements: Node.js 22.x (≥22.19), 24.x (≥24.11) or 26+, plus npm. REA never installs
analysis engines — Hopper, Ghidra, IDA, JADX, JDK, Binwalk, Unblob, mitmproxy and tshark are
bring-your-own.

## Tool mapping (condensed)

| Investigation need | REA tools |
| --- | --- |
| Open a target | `open_binary`, `open_bundle_resources`, `inspect_artifact` |
| Format/identity | `inspect_binary_layout`, `inspect_macho`, `inspect_pe_resources`, `inspect_managed_artifact` |
| Build metadata | `inspect_go_binary`, `inspect_rust_binary`, `inspect_il2cpp_metadata` |
| JS/Electron graph | `analyze_javascript_application`, `recover_javascript_sources` |
| Decompile / xrefs | `analyze_function`, `procedure_pseudo_code`, `list_procedures`, `search_strings`, `xrefs` |
| Runtime | `list_browser_targets`, `inspect_web_page`, `observe_web_session`, `capture_browser_scenario`, `list_electron_targets` |
| Network | `inspect_web_network_capture`, `inspect_pcap_capture`, `inspect_packet_capture` |
| Compare | `compare_artifacts`, `compare_functions`, `compare_application_versions` |
| Unknowns | `record_unknown`, `update_unknown` |
| Paging | `inspect_analysis_view`, `get_evidence_bundle`, `export_evidence_bundle` |

Full detail: `.kilo/skills/reverse-engineer/references/rea-tool-reference.md`.

## Rules when REA is connected

1. Use the connected server's actual tool list and schemas — a skill written against a newer
   release may describe tools an older server does not have.
2. Prefer `detail: "summary"` first; page the retained parent instead of re-running the producer.
3. `resource_constraint` with `details.resource: "transport"` means the reply was too large, not
   that the analysis failed.
4. Export evidence before closing a session — closing clears retained references.
5. Provider unavailability is **unknown**, not failure. Continue with the local ladder.

## Attribution

REA is MIT-licensed. This repository re-expresses its methodology for Kilo-based agentic work
and credits it in `LICENSE`, `README.md`, and this page. The REA project, its website
(<https://rea.tools>), and its Discord remain the property of their authors.

Commercial tools that REA can drive — IDA Pro/Hex-Rays, Hopper, JEB — must be legally obtained
and used under their own licences. This workspace grants no tool licence, key, or activation
entitlement, and contains no licence-bypass material.
