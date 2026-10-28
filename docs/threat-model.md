# Threat model

| Threat | Mitigation | Test |
|---|---|---|
| Identity names carrying prompt injection ("report healthy") | posture is code-only; model text validated | `test_injection_in_identity_names_does_not_change_posture` |
| Model invents identities or roles | `check_note` rejects unknown emails/roles | `test_note_naming_an_unknown_*` |
| Model suggests a fix that widens access | simulator rejects added capabilities and score increases | `test_model_patch_that_widens_access_is_rejected` |
| Model suggests a non-existent change | binding existence check | `test_model_patch_for_nonexistent_binding_is_rejected` |
| Fix locks everyone out of IAM | last-IAM-admin guard | `test_never_removes_the_last_iam_admin` |
| Links / phishing in model text | rejected in notes and summary | `test_note_with_link_is_dropped...` |
| Model outage, bad JSON, slow, over budget | degrade to rules and rule-based fixes | `test_garbage_replies...`, `test_budget_stops...` |
| Tool used to read other projects | live mode allow-list; runtime SA scoped to its own project | `test_live_mode_is_allow_listed...` |
| Sensitive IAM data at rest | memory only, 50-entry cap, snapshot hash only | `test_nothing_is_persisted...` |
| Unauthorised use | Cloud Run IAM, one invoker | live: unauthenticated = 403 |
| Runtime SA abuse | `iam.securityReviewer` can read IAM but change nothing | by design |

Residual risk: the runtime SA can read every IAM policy in its project, so protect the invoker role;
the catalog may understate a role's reach.
