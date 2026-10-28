# ADR 0002: every fix is verified by re-running the engine

**Decision**: a patch is applied to a copy of the snapshot and the engine is re-run; it is shown only if no principal
gains access, total radius falls, and the project keeps an IAM admin. Replacement roles must be catalog roles whose capabilities are a subset of the old role's.
**Why**: LLM-suggested IAM changes are plausible-sounding and sometimes wrong (widening, missing bindings, lock-out).
**Consequence**: some good suggestions are rejected (replacement roles outside the catalog); verification is against the model of access, not real usage.
