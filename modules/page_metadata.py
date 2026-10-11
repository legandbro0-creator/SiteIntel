"""Module G — lightweight page metadata.

We parse ONLY the (bounded) HTML the HTTP module already downloaded — zero
extra requests, no external resource downloads, no JavaScript execution.

Teaching note worth keeping in the report:
Many modern sites (React/Vue/Angular SPAs) render content in the browser with
JavaScript.  A CLI tool sees only the initial HTML shell.  Missing metadata
can mean "not present" OR "rendered later by JS" — the JSON report says so.
"""
from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

import config

JS_RENDER_NOTE = ("Initial HTML only, no JavaScript executed: JS-rendered (SPA) "
                  "sites may expose little/none of their real content here.")


def _absolutize(url: str, base: str) -> str:
    return urljoin(base, url.strip()) if url else url


def extract_metadata(html: str | None, base_url: str) -> dict:
    if not html:
        return {"status": "skipped",
                "note": "No HTML body available (error, redirect with no body, or non-HTML content-type).",
                "js_render_note": JS_RENDER_NOTE}

    soup = BeautifulSoup(html, "html.parser")

    def meta(attr: str, key: str) -> str | None:
        tag = soup.find("meta", attrs={attr: key})
        return tag["content"].strip() if tag and tag.get("content") else None

    open_graph = {}
    for tag in soup.find_all("meta", property=True):
        prop = tag.get("property", "")
        if prop.startswith("og:") and tag.get("content"):
            open_graph[prop] = tag["content"].strip()

    def links_with_rel(rel_name: str) -> list[str]:
        out = []
        for tag in soup.find_all("link", rel=True):
            rels = tag.get("rel") if isinstance(tag.get("rel"), list) else [tag.get("rel")]
            if rels and rel_name in [str(r).lower() for r in rels] and tag.get("href"):
                out.append(_absolutize(tag["href"], base_url))
        return out

    canonical = links_with_rel("canonical")
    icons = links_with_rel("icon") + links_with_rel("shortcut icon") + links_with_rel("apple-touch-icon")
    stylesheets = links_with_rel("stylesheet")[: config.MAX_LIST_ITEMS]
    scripts = [_absolutize(t["src"], base_url)
               for t in soup.find_all("script", src=True)][: config.MAX_LIST_ITEMS]

    title_tag = soup.find("title")
    return {
        "status": "ok",
        "title": title_tag.get_text(strip=True) if title_tag else None,
        "meta_description": meta("name", "description"),
        "canonical_url": canonical[0] if canonical else None,
        "language": (soup.html.get("lang") if soup.html and soup.html.get("lang") else None),
        "robots_meta": meta("name", "robots"),
        "generator_meta": meta("name", "generator"),
        "open_graph": open_graph,
        "favicon": icons[0] if icons else None,
        "stylesheets": stylesheets,
        "scripts": scripts,
        "link_count": len(soup.find_all("a")),
        "image_count": len(soup.find_all("img")),
        "truncated_lists_note": (f"Lists capped at {config.MAX_LIST_ITEMS} entries; "
                                 "HTML itself may be truncated at "
                                 f"{config.MAX_BODY_BYTES // 1024} KB."),
        "js_render_note": JS_RENDER_NOTE,
    }
