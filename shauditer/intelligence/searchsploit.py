"""Search local exploit-db index for public research metadata only.

Does not retrieve, compile, copy or execute exploit code.
"""
from __future__ import annotations
import json
import re
import shutil

from shauditer.security.runner import SafeProcessRunner

CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.I)


def parse_searchsploit_json(text: str) -> list[dict]:
    data = json.loads(text)
    items = []
    for row in (data.get("RESULTS_EXPLOIT") or [])[:50]:
        number = str(row.get("EDB-ID") or "").strip()
        if not number.isdecimal():
            continue
        items.append({"edb_id": number, "title": str(row.get("Title") or "")[:220],
                      "type": str(row.get("Type") or "")[:60],
                      "url": f"https://www.exploit-db.com/exploits/{number}"})
    return items


async def search_local(cves: list[str], runner: SafeProcessRunner | None = None) -> dict[str, list[dict]]:
    output = {}
    if not shutil.which("searchsploit"):
        return output
    runner = runner or SafeProcessRunner()
    for identifier in cves[:6]:
        matched = CVE.fullmatch(identifier)
        if not matched:
            continue
        result = await runner.execute("searchsploit", ["--cve", f"{matched.group(1)}-{matched.group(2)}", "--json"], timeout=15)
        if result.exit_code not in (0, 1) or result.timed_out or result.output_truncated:
            continue
        try:
            output[identifier] = parse_searchsploit_json(result.stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            output[identifier] = []
    return output
