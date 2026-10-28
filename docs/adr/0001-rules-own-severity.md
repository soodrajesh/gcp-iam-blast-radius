# ADR 0001: rules own severity and posture

**Decision**: a deterministic engine and rule set decide scores, severities and posture; models only explain and propose.
**Why**: identity names and descriptions are attacker-controlled text. A model that decides the verdict can be talked into "healthy".
**Consequence**: models add readability, not coverage; unlisted roles are a coverage gap, reported rather than guessed.
