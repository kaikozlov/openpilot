"""Human-friendly discovery helpers over a derived Toyota diagnostic registry."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re
from typing import Any

from tools.toyota_diag.registry import EcuSpec, Profile


@dataclass(frozen=True)
class SearchResult:
  kind: str
  ecu: EcuSpec | None
  identifier: str
  name: str
  detail: str = ""
  score: int = 0


def _score(query: str, fields: Iterable[str]) -> int:
  needle = query.casefold().strip()
  if not needle:
    return 0
  query_tokens = re.findall(r"[a-z0-9]+", needle)
  best = 0
  for field in fields:
    hay = field.casefold()
    field_tokens = re.findall(r"[a-z0-9]+", hay)
    if hay == needle:
      best = max(best, 100)
    elif hay.startswith(needle):
      best = max(best, 80)
    elif len(needle) >= 4 and needle in hay:
      best = max(best, 60)
    elif query_tokens and all(any(token == item or (len(token) >= 4 and item.startswith(token)) for item in field_tokens) for token in query_tokens):
      best = max(best, 55)
  return best


def _category_name(profile: Profile, ecu: EcuSpec) -> str:
  category = profile.category(ecu)
  if category is None:
    return ""
  meta = category.get("category", {})
  return str(meta.get("name") or meta.get("database") or "")


def search(profile: Profile, query: str, limit: int = 50) -> list[SearchResult]:
  results: list[SearchResult] = []
  for ecu in profile.ecus:
    category = profile.category(ecu)
    category_name = _category_name(profile, ecu)
    score = _score(query, (ecu.key, ecu.name, f"0x{ecu.address:X}", category_name))
    if score:
      results.append(SearchResult("ecu", ecu, f"0x{ecu.address:X}", ecu.name, category_name, score))
    if category is None:
      continue

    for did_hex, signals in category.get("dids", {}).items():
      names = [str(row.get("name") or "") for row in signals]
      score = _score(query, (did_hex, *names))
      if score:
        detail = ", ".join(name for name in names if name)
        results.append(SearchResult("did", ecu, did_hex, detail or "Data List item", category_name, score))

    for raw_hex, rows in category.get("dtcs", {}).items():
      for row in rows:
        code = str(row.get("code") or raw_hex)
        name = str(row.get("description") or "")
        failure = str(row.get("failure") or "")
        score = _score(query, (raw_hex, code, name, failure))
        if score:
          results.append(SearchResult("dtc", ecu, code, name or code, failure, score))

    for row in category.get("active_tests", []):
      ident = f"0x{int(row.get('id', 0)):04X}"
      name = str(row.get("name") or "")
      kind = str(row.get("kind") or "active-test")
      score = _score(query, (ident, name, kind))
      if score:
        execution = str(row.get("execution") or "")
        results.append(SearchResult("active-test", ecu, ident, name or ident, f"{kind} {execution}".strip(), score))

    for row in category.get("functions", []):
      ident = str(row.get("id") or row.get("function_id") or "")
      detail_id = row.get("detail_id")
      if detail_id is not None:
        ident = f"{ident}/{detail_id}"
      name = str(row.get("name") or row.get("detail_name") or "")
      score = _score(query, (ident, name, str(row)))
      if score:
        results.append(SearchResult("function", ecu, ident, name or "Function", str(row.get("semantic_kind") or ""), score))

    for row in category.get("roles", []):
      ident = str(row.get("role") or row.get("id") or "")
      name = str(row.get("plugin") or row.get("name") or "")
      semantic = str(row.get("semantic_kind") or row.get("kind") or "")
      score = _score(query, (ident, name, semantic))
      if score:
        results.append(SearchResult("role", ecu, ident, name or "Role", semantic, score))

    for row in category.get("utilities", []):
      ident = str(row.get("id") or row.get("routine_id") or "")
      name = str(row.get("name") or "")
      score = _score(query, (ident, name, str(row.get("kind") or "")))
      if score:
        results.append(SearchResult("utility", ecu, ident, name or "Utility", str(row.get("execution") or ""), score))

  results.sort(key=lambda row: (-row.score, row.kind, row.ecu.key if row.ecu else "", row.identifier, row.name))
  return results[:limit]


def render(results: list[SearchResult]) -> str:
  if not results:
    return "no matches"
  lines = []
  for row in results:
    ecu = row.ecu.key if row.ecu else "-"
    detail = f" — {row.detail}" if row.detail else ""
    lines.append(f"{row.kind:<12} {ecu:<18} {row.identifier:<10} {row.name}{detail}")
  return "\n".join(lines)


def summary_counts(profile: Profile, ecu: EcuSpec) -> dict[str, int]:
  category = profile.category(ecu)
  if category is None:
    return {"dids": 0, "signals": 0, "dtcs": 0, "active_tests": 0, "functions": 0, "roles": 0, "utilities": 0}
  dids = category.get("dids", {})
  dtcs = category.get("dtcs", {})
  return {
    "dids": len(dids),
    "signals": sum(len(rows) for rows in dids.values()),
    "dtcs": sum(len(rows) for rows in dtcs.values()),
    "active_tests": len(category.get("active_tests", [])),
    "functions": len(category.get("functions", [])),
    "roles": len(category.get("roles", [])),
    "utilities": len(category.get("utilities", [])),
  }


def flatten_signal_record(value: dict[str, Any]) -> list[dict[str, Any]]:
  rows = []
  for signal in value.get("signals", []):
    rendered = signal.get("pattern")
    if rendered is None:
      rendered = signal.get("value")
    rows.append({
      "ecu": value.get("ecu", {}).get("key"),
      "did": value.get("did"),
      "signal": signal.get("name") or "",
      "value": rendered,
      "numeric_value": signal.get("value"),
      "pattern": signal.get("pattern"),
      "raw": signal.get("raw"),
      "unit": signal.get("unit"),
      "error": signal.get("error"),
    })
  if not rows:
    rows.append({
      "ecu": value.get("ecu", {}).get("key"), "did": value.get("did"), "signal": "(raw)",
      "value": value.get("data_hex"), "numeric_value": None, "pattern": None, "raw": None, "unit": None,
      "error": None,
    })
  return rows
