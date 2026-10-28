# Runbook 01: deploy

1. `cp deploy.env.example deploy.env` and set `PROJECT_ID`, `REGION`, `ADMIN_EMAIL`.
2. `gcloud auth login && gcloud auth application-default login`.
3. `./scripts/up.sh`. It applies the foundation (APIs, registry, identities), builds the image, then deploys Cloud Run.
   Every Terraform change is a saved plan that the script summarises and refuses if it contains destroys (`ALLOW_DESTROY=1` overrides).
4. Open the UI: `gcloud run services proxy iam-blast --region us-central1 --port 8081`.
5. Verify: unauthenticated `curl <url>/` returns 403; `curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" <url>/api/config` returns JSON.

If the build fails right after the first apply, IAM grants for the build identity are still propagating; the script retries 3 times.
