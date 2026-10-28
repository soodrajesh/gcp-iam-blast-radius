# Runbook 04: an identity may be compromised

1. Analyze the project and open the identity in *Blast radius by principal*. The chips show what it holds directly (blue)
   and what it gains through service-account hops (red). That is the maximum an attacker could reach.
2. Contain: disable the identity or remove its enabling bindings (the verified fix for its IAM001 finding is a start).
   For a service account also delete user-managed keys.
3. Treat every SA in its reachable list as exposed: rotate keys, review audit logs for `GenerateAccessToken`,
   `SignJwt`, `CreateServiceAccountKey` and `SetIamPolicy` by that identity.
4. After containment re-analyze and confirm the radius is gone.
