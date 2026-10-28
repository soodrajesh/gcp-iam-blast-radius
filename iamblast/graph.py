"""The engine: from a snapshot, compute what each principal can directly do and which service
accounts it can *become*, then the effective capabilities across those hops.

A principal P can become service account S if any of these hold:
  * P has `impersonate_any` (or `iam_admin`, which can grant itself that) on the project
  * P has `key_create_any` on the project (it can mint a key for S)
  * P holds a token-creator / key-admin role on S itself
  * P can attach S (`actas_any` project-wide, or serviceAccountUser on S) AND can run code (`code_exec`)
Everything is a pure function of the snapshot, so results are reproducible and can be re-run on a
patched copy to verify a fix."""

from __future__ import annotations

from collections import deque

from . import catalog
from .models import Binding, Hop, Reach, Snapshot


def _caps(roles: list[str]) -> tuple[set[str], list[str]]:
    caps: set[str] = set()
    unknown: list[str] = []
    for r in roles:
        c = catalog.caps_of(r)
        if c is None:
            unknown.append(r)
        else:
            caps |= c
    return caps, unknown


class Engine:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.sas = {sa.member: sa for sa in snap.service_accounts if not sa.disabled}
        self.project_bindings: dict[str, list[Binding]] = {}
        self.sa_bindings: dict[tuple[str, str], list[Binding]] = {}  # (sa member, principal)
        self.unclassified: set[str] = set()
        for b in snap.bindings:
            if catalog.caps_of(b.role) is None and not (
                catalog.is_google_managed(b.member) or b.role.endswith(".serviceAgent")
            ):
                self.unclassified.add(b.role)
            if b.scope == "project":
                self.project_bindings.setdefault(b.member, []).append(b)
            elif b.scope.startswith("sa:"):
                self.sa_bindings.setdefault((f"serviceAccount:{b.scope[3:]}", b.member), []).append(
                    b
                )
        self.principals = sorted(
            set(self.project_bindings) | {p for (_, p) in self.sa_bindings} | set(self.sas)
        )
        self._direct = {p: self._direct_caps(p) for p in self.principals}
        self._hops = {p: self._edges(p) for p in self.principals}

    def _direct_caps(self, p: str) -> set[str]:
        caps, _ = _caps([b.role for b in self.project_bindings.get(p, [])])
        # Whoever can change IAM policy can grant themselves everything, so that is their radius.
        return set(catalog.ALL_CAPS) if "iam_admin" in caps else caps

    def _edges(self, p: str) -> list[Hop]:
        dc = self._direct[p]
        out: list[Hop] = []
        for sa_member in sorted(self.sas):
            if sa_member == p:
                continue
            hop = self._edge(p, dc, sa_member)
            if hop:
                out.append(hop)
        return out

    def _edge(self, p: str, dc: set[str], target: str) -> Hop | None:
        def proj(cap: str) -> Binding | None:
            return next(
                (
                    b
                    for b in self.project_bindings.get(p, [])
                    if cap in (catalog.caps_of(b.role) or ())
                ),
                None,
            )

        sa_level = self.sa_bindings.get((target, p), [])

        def on_sa(cap: str) -> Binding | None:
            return next((b for b in sa_level if cap in (catalog.caps_of(b.role) or ())), None)

        if b := proj("impersonate_any") or proj("iam_admin"):
            return Hop(
                source=p,
                target=target,
                binding=b,
                how="can mint tokens for any service account in the project"
                if "impersonate_any" in (catalog.caps_of(b.role) or ())
                else "can edit IAM policy, granting itself token creation",
            )
        if b := proj("key_create_any"):
            return Hop(
                source=p, target=target, binding=b, how="can create a key for any service account"
            )
        if b := on_sa("impersonate_any"):
            return Hop(
                source=p,
                target=target,
                binding=b,
                how="holds a token-creator role on this service account",
            )
        if b := on_sa("key_create_any"):
            return Hop(
                source=p, target=target, binding=b, how="can create keys for this service account"
            )
        attach = proj("actas_any") or on_sa("actas_any")
        execute = proj("code_exec")
        if attach and execute:
            return Hop(
                source=p,
                target=target,
                binding=attach,
                how=f"can attach it to code it runs (actAs via {attach.role}, execute via {execute.role})",
            )
        return None

    def reach(self, p: str) -> Reach:
        direct = self._direct.get(p, set())
        parent: dict[str, Hop] = {}
        order: list[str] = []
        seen, q = {p}, deque([p])
        while q:
            cur = q.popleft()
            for hop in self._hops.get(cur, []):
                if hop.target not in seen:
                    seen.add(hop.target)
                    parent[hop.target] = hop
                    order.append(hop.target)
                    q.append(hop.target)
        eff = set(direct)
        paths: dict[str, list[Hop]] = {}
        for t in order:
            eff |= self._direct.get(t, set())
            chain, cur = [], t
            while cur != p:
                chain.append(parent[cur])
                cur = parent[cur].source
            paths[t] = list(reversed(chain))
        ds, es = catalog.score(direct), catalog.score(eff)
        return Reach(
            principal=p,
            direct_caps=sorted(direct),
            effective_caps=sorted(eff),
            gained_caps=sorted(eff - direct),
            direct_score=ds,
            score=es,
            level=catalog.level(es),
            reachable=order,
            paths=paths,
        )

    def all_reach(self) -> list[Reach]:
        return sorted(
            (self.reach(p) for p in self.principals), key=lambda r: (-r.score, r.principal)
        )

    def total_score(self) -> int:
        return sum(r.score for r in self.all_reach())

    def graph(self) -> dict:
        """Nodes and escalation edges for the UI."""
        reaches = {r.principal: r for r in self.all_reach()}
        nodes = [
            {
                "id": p,
                "score": reaches[p].score,
                "level": reaches[p].level,
                "kind": "sa" if p in self.sas else p.split(":")[0] if ":" in p else "public",
            }
            for p in self.principals
        ]
        edges = [
            {"source": h.source, "target": h.target, "how": h.how, "role": h.binding.role}
            for p in self.principals
            for h in self._hops[p]
            # Owner/Editor reach every SA; drawing those would bury the interesting edges.
            # They are reported by rule IAM003 instead.
            if h.binding.role not in catalog.PRIMITIVE
        ]
        return {"nodes": nodes, "edges": edges}
