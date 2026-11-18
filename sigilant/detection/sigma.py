from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path

import yaml

from ..mitre import parse_tags
from ..models import Event

MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "all", "windash"}
LEVELS = {"informational", "low", "medium", "high", "critical"}


class SigmaError(ValueError):
    pass


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _windash_variants(value: str) -> list[str]:
    if "-" not in value:
        return [value]
    return list(dict.fromkeys([value, value.replace("-", "/"), value.replace("-", "–")]))


def match_value(actual, expected, mods: frozenset[str]) -> bool:
    if expected is None:
        return actual in (None, "")
    if actual is None:
        return False
    if isinstance(actual, (list, tuple)):
        return any(match_value(a, expected, mods) for a in actual)
    a, e = str(actual), str(expected)
    if "re" in mods:
        return re.search(e, a) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(a) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    al, el = a.lower(), e.lower()
    if "contains" in mods:
        return el in al
    if "startswith" in mods:
        return al.startswith(el)
    if "endswith" in mods:
        return al.endswith(el)
    if "*" in e or "?" in e:
        return _glob_regex(e).match(a) is not None
    return al == el


def _split_key(key: str) -> tuple[str, frozenset[str]]:
    name, *mods = key.split("|")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise SigmaError(f"Unsupported modifier(s) {sorted(unknown)} in '{key}'")
    return name, frozenset(mods)


def match_field(event: Event, key: str, expected) -> bool:
    name, mods = _split_key(key)
    values = expected if isinstance(expected, list) else [expected]
    if "windash" in mods:
        groups = [_windash_variants(str(v)) for v in values]
    else:
        groups = [[v] for v in values]
    actual = event.get(name)
    hits = (any(match_value(actual, v, mods) for v in variants) for variants in groups)
    return all(hits) if "all" in mods else any(hits)


def match_selection(event: Event, selection) -> bool:
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            return any(match_selection(event, s) for s in selection)
        text = str(event.get("message", "")).lower()
        return any(str(kw).lower() in text for kw in selection)
    raise SigmaError(f"Unsupported selection type: {type(selection).__name__}")


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenise(cond: str) -> list[str]:
    pos, toks = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"Cannot parse condition near: {cond[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
    return toks


class _Parser:

    def __init__(self, tokens: list[str]):
        self.toks, self.i = tokens, 0

    def peek(self):
        return self.toks[self.i].lower() if self.i < len(self.toks) else None

    def take(self):
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.expr()
        if self.peek() is not None:
            raise SigmaError(f"Unexpected token {self.toks[self.i]!r}")
        return node

    def expr(self):
        nodes = [self.term()]
        while self.peek() == "or":
            self.take()
            nodes.append(self.term())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def term(self):
        nodes = [self.factor()]
        while self.peek() == "and":
            self.take()
            nodes.append(self.factor())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def factor(self):
        tok = self.peek()
        if tok is None:
            raise SigmaError("Condition ended unexpectedly")
        if tok == "not":
            self.take()
            return ("not", self.factor())
        if tok == "(":
            self.take()
            node = self.expr()
            if self.peek() != ")":
                raise SigmaError("Missing closing parenthesis")
            self.take()
            return node
        if tok in ("1", "any", "all") and self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            quant = "all" if self.take().lower() == "all" else "any"
            self.take()
            return ("of", quant, self.take())
        if tok in ("and", "or", ")"):
            raise SigmaError(f"Unexpected {tok!r}")
        return ("sel", self.take())


def _selection_names(node, names: set[str]) -> None:
    kind = node[0]
    if kind == "sel":
        names.add(node[1])
    elif kind == "not":
        _selection_names(node[1], names)
    elif kind in ("and", "or"):
        for n in node[1]:
            _selection_names(n, names)


def _expand_of(pattern: str, available: list[str]) -> list[str]:
    if pattern.lower() == "them":
        return [n for n in available if not n.startswith("_")]
    return [n for n in available if fnmatch(n, pattern)]


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    logsource: dict
    detection: dict
    condition: str
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    status: str = "experimental"
    path: str = ""

    def __post_init__(self):
        self.selections = {k: v for k, v in self.detection.items() if k not in ("condition", "timeframe")}
        self.ast = _Parser(_tokenise(self.condition)).parse()
        names: set[str] = set()
        _selection_names(self.ast, names)
        missing = names - set(self.selections)
        if missing:
            raise SigmaError(f"Condition references unknown selection(s): {sorted(missing)}")
        for sel in self.selections.values():
            for item in (sel if isinstance(sel, list) else [sel]):
                if isinstance(item, dict):
                    for key in item:
                        _split_key(key)
        self.techniques, self.tactics = parse_tags(self.tags)

    @classmethod
    def from_dict(cls, doc: dict, path: str = "") -> "SigmaRule":
        for key in ("title", "id", "logsource", "detection", "level"):
            if key not in doc:
                raise SigmaError(f"{path or 'rule'}: missing required field '{key}'")
        if doc["level"] not in LEVELS:
            raise SigmaError(f"{path}: invalid level {doc['level']!r}")
        detection = doc["detection"]
        if "condition" not in detection:
            raise SigmaError(f"{path}: detection.condition is required")
        cond = detection["condition"]
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        return cls(id=str(doc["id"]), title=doc["title"], level=doc["level"],
                   description=doc.get("description", ""), logsource=doc["logsource"],
                   detection=detection, condition=cond, tags=doc.get("tags", []),
                   falsepositives=doc.get("falsepositives", []), status=doc.get("status", "experimental"),
                   path=path)

    def logsource_matches(self, event: Event) -> bool:
        return all(event.get(f"logsource.{k}") == v for k, v in self.logsource.items()
                   if k in ("product", "service", "category"))

    def _eval(self, node, event: Event, cache: dict) -> bool:
        kind = node[0]
        if kind == "sel":
            name = node[1]
            if name not in cache:
                cache[name] = match_selection(event, self.selections[name])
            return cache[name]
        if kind == "not":
            return not self._eval(node[1], event, cache)
        if kind == "and":
            return all(self._eval(n, event, cache) for n in node[1])
        if kind == "or":
            return any(self._eval(n, event, cache) for n in node[1])
        if kind == "of":
            _, quant, pattern = node
            names = _expand_of(pattern, list(self.selections))
            results = (self._eval(("sel", n), event, cache) for n in names)
            return all(results) if quant == "all" else any(results)
        raise SigmaError(f"Bad AST node {node!r}")

    def matches(self, event: Event) -> bool:
        return self.logsource_matches(event) and self._eval(self.ast, event, {})

    def to_query(self, target: str) -> str:
        conv = _SPL if target == "splunk" else _KQL
        body = conv.node(self.ast, self)
        src = ", ".join(f"{k}={v}" for k, v in self.logsource.items())
        if target == "splunk":
            return f"`comment(\"{self.title} | logsource: {src}\")`\nsearch {body}"
        return f"// {self.title} | logsource: {src}\nEvents\n| where {body}"


def load_rules(directory: Path) -> list[SigmaRule]:
    rules = []
    for path in sorted(Path(directory).rglob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    rules.append(SigmaRule.from_dict(doc, str(path)))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SigmaError(f"Duplicate rule ids: {sorted(dupes)}")
    return rules


def _q(v: str) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


class _Backend:
    @classmethod
    def node(cls, node, rule: SigmaRule) -> str:
        kind = node[0]
        if kind == "sel":
            return cls.selection(rule.selections[node[1]])
        if kind == "not":
            return f"NOT ({cls.node(node[1], rule)})" if cls is _SPL else f"not ({cls.node(node[1], rule)})"
        if kind in ("and", "or"):
            joiner = f" {kind.upper()} " if cls is _SPL else f" {kind} "
            return "(" + joiner.join(cls.node(n, rule) for n in node[1]) + ")"
        _, quant, pattern = node
        names = _expand_of(pattern, list(rule.selections))
        return cls.node(("and" if quant == "all" else "or", [("sel", n) for n in names]), rule)

    @classmethod
    def selection(cls, sel) -> str:
        if isinstance(sel, dict):
            parts = [cls.field(k, v) for k, v in sel.items()]
            return "(" + cls.AND.join(parts) + ")"
        if all(isinstance(s, dict) for s in sel):
            return "(" + cls.OR.join(cls.selection(s) for s in sel) + ")"
        return "(" + cls.OR.join(cls.keyword(k) for k in sel) + ")"

    @classmethod
    def field(cls, key, expected) -> str:
        name, mods = _split_key(key)
        values = expected if isinstance(expected, list) else [expected]
        terms = []
        for v in values:
            variants = _windash_variants(str(v)) if "windash" in mods and v is not None else [v]
            terms.append("(" + cls.OR.join(cls.term(name, x, mods) for x in variants) + ")"
                         if len(variants) > 1 else cls.term(name, variants[0], mods))
        joiner = cls.AND if "all" in mods else cls.OR
        return terms[0] if len(terms) == 1 else "(" + joiner.join(terms) + ")"


class _SPL(_Backend):
    AND, OR = " ", " OR "

    @staticmethod
    def term(name, v, mods):
        if v is None:
            return f"NOT {name}=*"
        v = str(v)
        if "re" in mods:
            return f'| regex {name}={_q(v)}'
        if "contains" in mods:
            v = f"*{v}*"
        elif "startswith" in mods:
            v = f"{v}*"
        elif "endswith" in mods:
            v = f"*{v}"
        return f"{name}={_q(v)}"

    @staticmethod
    def keyword(k):
        return _q(k)


class _KQL(_Backend):
    AND, OR = " and ", " or "

    @staticmethod
    def term(name, v, mods):
        col = f"['{name}']" if not re.fullmatch(r"[A-Za-z_]\w*", name) else name
        if v is None:
            return f"isempty({col})"
        v = str(v)
        if "re" in mods:
            return f"{col} matches regex {_q(v)}"
        if "cidr" in mods:
            return f"ipv4_is_in_range({col}, {_q(v)})"
        for mod, op in (("contains", "contains"), ("startswith", "startswith"), ("endswith", "endswith")):
            if mod in mods:
                return f"{col} {op} {_q(v)}"
        if "*" in v or "?" in v:
            rx = _glob_regex(v).pattern
            return f"{col} matches regex {_q('(?i)' + rx)}"
        return f"{col} =~ {_q(v)}"

    @staticmethod
    def keyword(k):
        return f"tostring(pack_all()) contains {_q(k)}"
