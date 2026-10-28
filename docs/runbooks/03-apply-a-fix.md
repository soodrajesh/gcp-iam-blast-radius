# Runbook 03: apply a verified fix

1. Pick a fix in *Verified fixes*. "Accepted" means the simulator showed blast radius going down and no
   one gaining access. It does **not** mean the workload still works.
2. Check usage first: Cloud Audit Logs / Policy Analyzer for the member and role over the last 90 days.
3. Apply the commands in order (for a replacement the narrower role is added before the old one is removed).
4. Re-run the analysis; the finding should be gone and the total score lower than before.
5. Keep the pre-change snapshot for rollback: re-add the removed binding with the same command shape.
