import json
from importlib import resources

from iamblast.llm import LLM, LLMResult


def sample(name: str) -> dict:
    return json.loads((resources.files("iamblast") / "samples" / f"{name}.json").read_text())


def snap(bindings, sas=(), domains=("acme.com",)):
    """bindings: (member, role[, scope]) tuples; sas: emails (or (email, disabled))."""
    out = []
    for b in bindings:
        m, r = b[0], b[1]
        out.append({"scope": b[2] if len(b) > 2 else "project", "role": r, "member": m})
    accounts = []
    for s in sas:
        email, disabled = (s, False) if isinstance(s, str) else s
        accounts.append({"email": email, "disabled": disabled, "keys": []})
    return {
        "project": "p",
        "internal_domains": list(domains),
        "bindings": out,
        "service_accounts": accounts,
    }


class ScriptedLLM(LLM):
    name, model = "scripted", "scripted-1"

    def __init__(self, reply=None, *, raises=None, delay=0.0):
        self.reply, self.raises, self.delay, self.calls = reply, raises, delay, 0

    async def complete_json(self, system, user, max_tokens=1200):
        import asyncio

        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises:
            raise self.raises
        r = self.reply(json.loads(user)) if callable(self.reply) else self.reply
        return LLMResult(r if isinstance(r, str) else json.dumps(r), 100, 50, 0.001)
