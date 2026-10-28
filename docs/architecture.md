# Architecture

**Collection** (`collector.py`): four read-only REST calls with Application Default Credentials:
project `getIamPolicy` (v3, so conditions stay conditions), service-account list, each SA's
`getIamPolicy`, each SA's user-managed keys. The result is a `Snapshot`; its SHA-256 is all that is
retained by the service.

**Engine** (`graph.py`). Each role maps to capabilities (`catalog.py`, e.g. `code_exec`, `actas_any`,
`iam_admin`). A principal can *become* service account S when it can mint tokens for it, create keys for
it, hold a token-creator role on it, or attach it to code it can run (`actAs` plus `code_exec`). Holding
`iam_admin` counts as everything, since it can grant itself any role. Reachability is a BFS over those
edges (shortest chain per target, cycles safe). Effective capabilities are the union along the chain;
score = capped weighted sum (iam_admin 40 ... actas 5).

**Rules** (`rules.py`): IAM001 escalation via hops, 002 public principals, 003 primitive roles, 004
external identities, 005 user-managed keys (old = high), 006 long chains, 007 project-wide
actAs/token-creator, 008 disabled SAs with roles, 009 catalog coverage, 010 IAM-admin holders.
Posture: any critical = `critical`; any high or 3+ medium = `needs_attention`; else `healthy`.

**Agents** (`agents.py`, `orchestrator.py`) run in parallel under one `Budget` (12 calls, $0.05):
- *Analyst* (top 4 escalations): note validated by `check_note` (no links; every email and `roles/...`
  token must exist in the snapshot or catalog).
- *Planner* (top 4 fixable findings): proposes remove/replace for one existing binding.
- *Verifier* (`remediate.py`): for every proposal and every rule-based default patch, applies it to a
  deep copy and re-runs the engine. Accepted only if the binding exists, a replacement is in the catalog
  and a subset of the old role's capabilities, no principal's score rises, total score drops, and the
  project keeps an identity able to change IAM.
- *Judge*: posture from rules; summary from the model with a template fallback.

**Failure handling**: model error, bad JSON, timeout or exhausted budget removes explanations only;
rule findings and rule-based fixes always appear and the gap is listed in `degraded`.
