"""A Cedar front-end that compiles to Mira's hashed rule bundle.

Cedar has become the dominant policy language for agent and MCP authorization
— ToolHive, IBM ContextForge and AWS Cedar for Agents all speak it. Asking an
enterprise that already writes Cedar to learn a bespoke DSL is a tax on
adoption, so this reads Cedar and produces the same content-addressed bundle
the gate already evaluates.

**This is a strict subset, and it refuses everything outside it.**

That refusal is the whole design. A policy compiler that silently ignores a
clause it does not understand will one day drop a `forbid` and permit
something catastrophic. So anything unrecognised raises `CedarError` at
compile time, where a human is watching, rather than at 3am inside an agent.

Supported:

    permit (principal, action == Action::"deploy", resource)
    when { resource.target_instance == "dev" };

    forbid (principal, action, resource)
    when { resource.target_instance == "prod" };

    @id("BOD-1.1")
    @description("No autonomous deployment to Production.")
    forbid (principal, action == Action::"deploy", resource)
    when { resource.target_instance == "prod" };

  - effects: permit, forbid
  - scope: principal / resource must be unconstrained; action may be
    `action` or `action == Action::"name"` or `action in [Action::"a", ...]`
  - conditions: `when { ... }` over `resource.<field> == "literal"` and
    `resource.<field> in ["a", "b"]`, joined by `&&`
  - annotations: @id and @description carry through to the bundle

Not supported (and rejected loudly): `unless`, `has`, `like`, `if/then/else`,
arithmetic, set operations beyond `in`, entity hierarchies (`in` over
principals), context references, and `||`. Several of those are expressible in
Cedar but not in the deterministic first-match evaluator Mira's gate uses, and
compiling them into something *approximately* equivalent would be worse than
refusing.

Ordering: Cedar is order-independent with forbid-overrides. Mira's gate is
first-match. To preserve Cedar's semantics exactly, every `forbid` is emitted
before every `permit`, which makes first-match evaluation agree with
forbid-overrides for the subset above.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .policy import PolicyBundle, Rule

__all__ = ["CedarError", "compile_cedar", "cedar_to_bundle"]


class CedarError(ValueError):
    """A Cedar policy this compiler will not translate.

    Raised rather than warned: a policy that partially compiled is a policy
    nobody can reason about.
    """


# ---- lexical helpers -------------------------------------------------------

_COMMENT = re.compile(r"//[^\n]*")
_ANNOTATION = re.compile(r'@(\w+)\(\s*"((?:[^"\\]|\\.)*)"\s*\)')
_EFFECT = re.compile(r"\b(permit|forbid)\b\s*\(", re.I)
_ACTION_EQ = re.compile(r'action\s*==\s*Action::"([^"]+)"')
_ACTION_IN = re.compile(r"action\s+in\s*\[([^\]]*)\]")
_ACTION_LIST_ITEM = re.compile(r'Action::"([^"]+)"')
_COND_EQ = re.compile(r'resource\.(\w+)\s*==\s*"([^"]*)"')
_COND_IN = re.compile(r"resource\.(\w+)\s+in\s*\[([^\]]*)\]")
_STR_ITEM = re.compile(r'"([^"]*)"')

_UNSUPPORTED = [
    (re.compile(r"\bunless\b"), "`unless` clauses"),
    (re.compile(r"\bhas\b"), "`has` attribute tests"),
    (re.compile(r"\blike\b"), "`like` string matching"),
    (re.compile(r"\bif\b\s"), "`if/then/else` expressions"),
    (re.compile(r"\|\|"), "`||` disjunction"),
    (re.compile(r"\bcontext\b"), "`context` references"),
    (re.compile(r"\bprincipal\s+in\b"), "principal hierarchies"),
    (re.compile(r"\bresource\s+in\b"), "resource hierarchies"),
    (re.compile(r"[<>]=?|!="), "inequality and negation operators"),
]


@dataclass
class _Statement:
    text: str
    annotations: dict[str, str]


def _strip_comments(src: str) -> str:
    return _COMMENT.sub("", src)


def _split_statements(src: str) -> list[_Statement]:
    """Split on top-level semicolons, keeping each statement's annotations."""
    out: list[_Statement] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    for ch in src:
        if ch == '"':
            in_str = not in_str
        if not in_str:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth == 0:
                text = "".join(buf).strip()
                if text:
                    anns = {k: v for k, v in _ANNOTATION.findall(text)}
                    out.append(_Statement(_ANNOTATION.sub("", text).strip(), anns))
                buf = []
                continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        anns = {k: v for k, v in _ANNOTATION.findall(tail)}
        out.append(_Statement(_ANNOTATION.sub("", tail).strip(), anns))
    return out


def _reject_unsupported(text: str, where: str) -> None:
    for pattern, what in _UNSUPPORTED:
        if pattern.search(text):
            raise CedarError(
                f"{where}: {what} are not supported by the Mira gate. "
                "Rewrite the policy, or express it directly as a Mira rule — "
                "this compiler refuses rather than approximating."
            )


def _parse_conditions(text: str, where: str) -> dict:
    """Parse the `when { ... }` body into the gate's match map."""
    m = re.search(r"when\s*\{(.*)\}", text, re.S)
    if not m:
        return {}
    body = m.group(1).strip()
    if not body:
        return {}
    _reject_unsupported(body, where)

    match: dict = {}
    consumed = body
    for field, value in _COND_EQ.findall(body):
        match[field] = value
        consumed = _COND_EQ.sub("", consumed, count=1)
    for field, items in _COND_IN.findall(body):
        match[field] = _STR_ITEM.findall(items)
        consumed = _COND_IN.sub("", consumed, count=1)

    leftover = consumed.replace("&&", "").strip()
    if leftover:
        raise CedarError(
            f"{where}: could not translate condition fragment {leftover!r}. "
            "Only `resource.field == \"literal\"` and "
            "`resource.field in [\"a\", \"b\"]` joined by && are supported."
        )
    return match


def compile_cedar(source: str, *, bundle_id: str, version: str) -> PolicyBundle:
    """Compile Cedar policy text into a Mira PolicyBundle.

    Raises CedarError on anything outside the supported subset.
    """
    src = _strip_comments(source)
    statements = _split_statements(src)
    if not statements:
        raise CedarError("no Cedar policies found in the source")

    forbids: list[Rule] = []
    permits: list[Rule] = []

    for i, st in enumerate(statements, start=1):
        where = st.annotations.get("id") or f"policy #{i}"
        eff = _EFFECT.search(st.text)
        if not eff:
            raise CedarError(f"{where}: statement does not begin with permit( or forbid(")
        effect = "allow" if eff.group(1).lower() == "permit" else "deny"

        scope_end = st.text.find(")", eff.end() - 1)
        if scope_end == -1:
            raise CedarError(f"{where}: unterminated scope — missing ')'")
        scope = st.text[eff.end():scope_end]
        _reject_unsupported(scope, where)

        match: dict = {}
        if (am := _ACTION_EQ.search(scope)):
            match["action"] = am.group(1)
        elif (am := _ACTION_IN.search(scope)):
            actions = _ACTION_LIST_ITEM.findall(am.group(1))
            if not actions:
                raise CedarError(f"{where}: `action in [...]` listed no actions")
            match["action"] = actions
        elif "action" not in scope:
            raise CedarError(f"{where}: scope must name principal, action and resource")

        match.update(_parse_conditions(st.text, where))

        if not match:
            raise CedarError(
                f"{where}: policy constrains nothing. An unconditional permit "
                "would allow every action; write it explicitly as a Mira rule "
                "if that is genuinely intended."
            )

        rule = Rule(
            id=st.annotations.get("id") or f"CEDAR-{i}",
            effect=effect,
            description=st.annotations.get("description")
            or f"compiled from Cedar policy #{i}",
            match=match,
        )
        (forbids if effect == "deny" else permits).append(rule)

    # Cedar is forbid-overrides and order-independent; the gate is first-match.
    # Emitting every forbid first makes the two agree for this subset.
    return PolicyBundle(
        bundle_id=bundle_id,
        version=version,
        rules=tuple(forbids + permits),
        default_effect="deny",
    )


def cedar_to_bundle(path: str, *, bundle_id: str, version: str) -> PolicyBundle:
    """Compile a .cedar file."""
    from pathlib import Path

    return compile_cedar(Path(path).read_text(), bundle_id=bundle_id, version=version)
