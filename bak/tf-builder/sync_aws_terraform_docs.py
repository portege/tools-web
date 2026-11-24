from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

GITHUB_TREE_URL = (
    "https://api.github.com/repos/hashicorp/terraform-provider-aws/git/trees/main?recursive=1"
)
RAW_DOCS_BASE = (
    "https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/website/docs/r"
)
USER_AGENT = "TerraformBuilderCatalogSync/1.1"

SERVICE_ACCENTS = [
    "#38bdf8",
    "#fb923c",
    "#34d399",
    "#a78bfa",
    "#f59e0b",
    "#2dd4bf",
    "#f472b6",
    "#818cf8",
]


def _headers(accept: str = "*/*") -> dict[str, str]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


def fetch_json(url: str) -> dict[str, Any]:
    req = Request(url, headers=_headers("application/vnd.github+json"))
    with urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_text(url: str) -> str | None:
    req = Request(url, headers=_headers("text/plain"))
    try:
        with urlopen(req, timeout=25) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError):
        return None


def infer_field_type(desc: str) -> str:
    low = desc.lower()
    if re.search(r"\b(boolean|true\s+or\s+false|whether\s+to\s+enable)\b", low):
        return "boolean"
    if re.search(r"\b(int|integer|number\s+of|port|seconds|memory|size|timeout|count)\b", low):
        return "number"
    return "text"


def parse_frontmatter_and_fields(md: str) -> tuple[str, str, list[dict[str, Any]]]:
    subcategory = "AWS"
    title = ""

    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", md, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        sub_m = re.search(r'^subcategory:\s*"?([^"\n]+)"?\s*$', fm, re.MULTILINE)
        if sub_m:
            subcategory = sub_m.group(1).strip()
        page_m = re.search(r'^page_title:\s*"?([^"\n]+)"?\s*$', fm, re.MULTILINE)
        if page_m:
            title = page_m.group(1).split(":")[0].strip()

    fields: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in md.splitlines():
        match = re.match(r"^\s*\*\s+`([a-z0-9_]+)`\s*-\s*(.+)$", line, re.IGNORECASE)
        if not match:
            continue

        key, desc = match.group(1), match.group(2).strip()
        if key in seen or key in {"tags", "tags_all"}:
            continue
        seen.add(key)

        fields.append(
            {
                "key": key,
                "label": key.replace("_", " ").title(),
                "type": infer_field_type(desc),
                "required": bool(re.search(r"\(required\)", desc, re.IGNORECASE)),
                "description": desc,
            }
        )

        if len(fields) >= 12:
            break

    return subcategory, title, fields


def process_doc_path(doc_path: str, index: int) -> tuple[str, dict[str, Any]] | None:
    # doc_path example: website/docs/r/vpc.html.markdown
    filename = doc_path.rsplit("/", 1)[-1]
    slug = filename.removesuffix(".html.markdown")
    if not slug:
        return None

    md = fetch_text(f"{RAW_DOCS_BASE}/{filename}")
    if not md:
        return None

    service, title, fields = parse_frontmatter_and_fields(md)
    tf_type = slug if slug.startswith("aws_") else f"aws_{slug}"

    defaults: dict[str, Any] = {}
    for f in fields[:6]:
        if f["type"] == "boolean":
            defaults[f["key"]] = False
        elif f["type"] == "number":
            defaults[f["key"]] = 0
        else:
            defaults[f["key"]] = ""

    spec: dict[str, Any] = {
        "type": tf_type,
        "service": service,
        "category": service,
        "label": title or tf_type,
        "shortType": tf_type,
        "accent": SERVICE_ACCENTS[index % len(SERVICE_ACCENTS)],
        "defaultName": re.sub(r"^aws_", "", tf_type),
        "defaults": defaults,
        "fields": fields,
        "outputs": ["id"],
    }
    return tf_type, spec


def main(max_workers: int = 12, limit: int | None = 50) -> None:
    tree_data = fetch_json(GITHUB_TREE_URL)
    doc_paths = [
        item["path"]
        for item in (tree_data.get("tree") or [])
        if item.get("type") == "blob"
        and str(item.get("path", "")).startswith("website/docs/r/")
        and str(item.get("path", "")).endswith(".html.markdown")
    ]

    if limit is not None:
        doc_paths = doc_paths[:limit]

    resources: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(process_doc_path, p, idx): p for idx, p in enumerate(doc_paths)
        }
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                tf_type, spec = res
                resources[tf_type] = spec

    out_dir = Path("data")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "aws_terraform_catalog.json"

    payload = {
        "provider": "hashicorp/aws",
        "source": "github.com/hashicorp/terraform-provider-aws",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "resources": dict(sorted(resources.items())),
    }

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Saved {len(resources)} AWS resources to {out_path}")


if __name__ == "__main__":
    # Tip: set GITHUB_TOKEN in env to avoid GitHub API rate limits on full runs (limit=None)
    main(max_workers=12, limit=None)
