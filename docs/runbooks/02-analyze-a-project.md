# Runbook 02: analyze a project

**Live (deployed service)**: choose the project in the UI and press *Analyze live project*, or
`POST /api/analyses {"live_project": "<id>"}`. The project must be in `IAMBLAST_LIVE_PROJECTS`.
To add one: grant the runtime SA `roles/iam.securityReviewer` on it and add it to the variable.

**Offline**: `iamblast collect <project> --internal-domain <your-domain> > snapshot.json` (read-only),
then `iamblast analyze snapshot.json --llm vertex`. Treat `snapshot.json` as sensitive.

**Reading the result**: start with `critical` IAM001 findings. The evidence line is the chain
`principal -> SA -> SA`; each hop names the binding that enables it. Then IAM002 (public) and IAM003 (primitive roles).
If `unclassified_roles` is non-empty, scores may be understated for those roles; add them to `catalog.py`.
