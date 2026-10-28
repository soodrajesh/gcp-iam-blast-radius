# Runbook 05: tear down

`./scripts/down.sh` (type the project id) or `./scripts/down.sh --yes`. It plans a destroy, prints every resource, and
applies that saved plan. The shared state bucket `<project>-tfstate` and enabled APIs are left in place.
Nothing else needs cleaning up: the service stores nothing.
