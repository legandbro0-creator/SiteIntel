"""HTTP inspector (spec §3A/§14).

One careful GET, following redirects MANUALLY hop by hop:
* every hop's status + Location is recorded and normalised
  (relative, scheme-relative and absolute destinations),
* loops and hop-count are capped,
* CROSS-ORIGIN hops must pass SSRF validation (core/validation) — a server
  cannot steer our scanner into private/link-local/loopback space,
* the final body is streamed and truncated at config.MAX_BODY_BYTES
  (mobile RAM),
* `set-cookie` header values are stripped from stored copies; cookies are
  kept as parsed name/attribute records (value length only),
* query values of sensitive parameters are redacted in every stored URL.

HEAD vs GET: we use GET because servers may answer HEAD differently.

"Was the redirect to HTTPS?" answers are computed in modules/security.py
from THIS module's explicit evidence — including `tested` flags that say
exactly what was and wasn't tried.
"""
from __future__ import annotations

import re
import time

import httpx

import config
from core.errors import SSRFBlocked
from core.models import INFO, INCONCLUSIVE, WARN, Finding
from core.target import TargetInfo, redact_url, safe_join_url
from core.validation import validate_destination

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_JS_NAV_RE = re.compile(rb"<meta[^>]+http-equiv=[\"']?refresh|window\.location|location\.replace\s*\(",
                        re.IGNORECASE)


def parse_set_cookie(value: str, source_url: str) -> dict:
    """Parse one Set-Cookie header.  The VALUE is never stored — only its
    length — because values can be session tokens (spec §3D)."""
    parts = [part.strip() for part in value.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {"secure": False, "httponly": False, "samesite": None,
             "path": None, "domain": None, "expires": None, "max-age": None}
    for part in parts[1:]:
        key, _, v = part.partition("=")
        key = key.lower()
        if key in ("secure", "httponly"):
            attrs[key] = True
        elif key == "samesite":
            attrs["samesite"] = v.lower() or None
        elif key in attrs:
            attrs[key] = v
    return {"name": name, "source": source_url, "value_length": len(val),
            "attributes": attrs}


def _origin(url: str) -> tuple[str, str, int]:
    parts = httpx.URL(url)
    return parts.scheme.lower(), parts.host.lower(), parts.port or (443 if parts.scheme == "https" else 80)


def _classify(exc: httpx.RequestError) -> tuple[str, str]:
    msg = str(exc) or type(exc).__name__
    lowered = msg.lower()
    if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return "timeout", f"Request timed out: {msg}"
    if "certificate" in lowered or "ssl" in lowered or "tls" in lowered:
        return "tls_error", f"TLS failure during HTTP request: {msg}"
    if isinstance(exc, httpx.ConnectError):
        return "connection_failed", f"Could not connect: {msg}"
    return "request_error", f"{type(exc).__name__}: {msg}"


def _client(settings, follow: bool = False) -> httpx.Client:
    timeout = httpx.Timeout(connect=settings.connect_timeout, read=settings.read_timeout,
                            write=settings.read_timeout, pool=settings.connect_timeout)
    return httpx.Client(timeout=timeout, follow_redirects=False, max_redirects=0,
                        headers={"User-Agent": settings.user_agent,
                                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                        limits=httpx.Limits(max_connections=4))


def follow_chain(start_url: str, settings, validate_cross_origin: bool = True):
    """Manual redirect following with per-hop evidence + SSRF validation.

    Returns (hops, final_response_holder, chain_error).
    final_response_holder: {"response": httpx.Response|None, "ttfb_ms":..., "body":bytes, "truncated":bool, "total_ms":...}
    """
    hops: list[dict] = []
    seen: set[str] = set()
    current = start_url
    client = _client(settings)
    holder = {"response": None, "ttfb_ms": None, "body": b"", "truncated": False,
              "total_ms": None}
    chain_error: dict | None = None
    try:
        for _ in range(settings.max_redirects + 1):
            if current in seen:
                chain_error = {"kind": "redirect_loop",
                               "message": f"Redirect loop detected at {redact_url(current)}"}
                break
            seen.add(current)
            started = time.perf_counter()
            with client.stream("GET", current) as response:
                ttfb = (time.perf_counter() - started) * 1000
                status = response.status_code
                location = response.headers.get("location")
                hop = {"hop": len(hops) + 1, "url": redact_url(current),
                       "status": status, "location": redact_url(location) if location else None,
                       "server": response.headers.get("server"),
                       "set_cookies": len(response.headers.get_list("set-cookie")),
                       "elapsed_ms": round(ttfb, 1)}
                hops.append(hop)

                is_redirect = status in REDIRECT_STATUSES and location
                if not is_redirect:
                    body = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes(chunk_size=16384):
                        body.extend(chunk)
                        if len(body) >= settings.max_body:
                            truncated = True
                            del body[settings.max_body:]
                            break
                    holder.update(response=response, ttfb_ms=round(ttfb, 1), body=bytes(body),
                                  truncated=truncated,
                                  total_ms=round((time.perf_counter() - started) * 1000, 1))
                    return hops, holder, chain_error
                body_discard = response.read()  # required before close; usually tiny
                del body_discard

            dest = safe_join_url(current, location)
            same_origin = _origin(dest) == _origin(current)
            if validate_cross_origin and not same_origin:
                try:
                    dest = validate_destination(dest)
                except SSRFBlocked as exc:
                    chain_error = {"kind": "ssrf_blocked", "message": str(exc),
                                   "blocked_url": redact_url(dest)}
                    break
            current = dest
        else:
            chain_error = {"kind": "too_many_redirects",
                           "message": f"Exceeded {settings.max_redirects} hops without a final response"}
    finally:
        client.close()
    return hops, holder, chain_error


def _finalised(final_response: httpx.Response | None, holder: dict, target: TargetInfo) -> dict | None:
    if final_response is None:
        return None
    url = str(final_response.url)
    headers = {k.lower(): v for k, v in final_response.headers.items()}
    if "set-cookie" in headers:
        headers["set-cookie"] = config.REDACTED + " (parsed into the cookies section below)"
    content_type = headers.get("content-type", "")
    html_excerpt = None
    if "text/html" in content_type or not content_type:
        charset = final_response.charset_encoding or "utf-8"
        html_excerpt = holder["body"][: config.MAX_HTML_EXCERPT].decode(charset, "replace")
    return {
        "url": redact_url(url),
        "scheme": final_response.url.scheme,
        "hostname": final_response.url.host,
        "port": final_response.url.port or (443 if final_response.url.scheme == "https" else 80),
        "path": final_response.url.path,
        "status": final_response.status_code,
        "reason": final_response.reason_phrase,
        "http_version": final_response.http_version,
        "headers": headers,
        "content_type": content_type,
        "content_length_header": headers.get("content-length"),
        "bytes_downloaded": len(holder["body"]),
        "content_encoding": headers.get("content-encoding"),
        "truncated": holder["truncated"],
        "server_header": headers.get("server"),
    }


def inspect_http(target: TargetInfo, settings) -> dict:
    findings: list[Finding] = []
    result: dict = {"status": "ok", "url_requested": redact_url(target.normalized_url),
                    "query_param_names": target.to_dict()["query_param_names"]}
    try:
        hops, holder, chain_error = follow_chain(target.normalized_url, settings)
    except httpx.InvalidURL as exc:
        return dict(result, status="error", findings=findings,
                    error_kind="bad_url", error=f"Invalid request URL: {exc}")
    except httpx.RequestError as exc:
        kind, msg = _classify(exc)
        return dict(result, status="error", findings=findings, error_kind=kind, error=msg)

    result["chain"] = hops
    result["redirected"] = len(hops) > 1
    result["chain_error"] = chain_error
    final = _finalised(holder.get("response"), holder, target)

    cookies: list[dict] = []
    if holder.get("response") is not None:
        for raw in holder["response"].headers.get_list("set-cookie"):
            cookies.append(parse_set_cookie(raw, final["url"] if final else "?"))
    result["cookies"] = cookies
    result["hop_set_cookie_counts"] = {h["hop"]: h["set_cookies"] for h in hops if h.get("set_cookies")}

    if len(hops) > 1:
        desc = " → ".join(f"{h['status']} {h['url']}" for h in hops)
        findings.append(Finding(
            name="redirect_chain", module="http", status=INFO,
            evidence=f"{len(hops)} hop(s): {desc}"[:400],
            why="Redirect chains change the effective origin of a scan; findings apply to the FINAL URL.",
            limitations=["First-hop URL is what you typed; each hop was requested exactly once."],
            recommendation="Link directly to the final URL to reduce latency and downgrade risk."))
    if chain_error and chain_error["kind"] == "ssrf_blocked":
        findings.append(Finding(
            name="redirect_destination_blocked", module="http", status=WARN, severity="low",
            evidence=chain_error["message"],
            why="Following this redirect would reach a non-public/internal address; the scan stopped at the previous hop.",
            limitations=["The stated destination was validated by DNS + address-family checks; "
                         "DNS could re-resolve differently at request time (TOCTOU)."],
            recommendation="If you own this site, check why it redirects to internal addresses."))
    if chain_error and chain_error["kind"] == "redirect_loop":
        findings.append(Finding(
            name="redirect_loop", module="http", status=WARN, severity="low",
            evidence=chain_error["message"],
            why="A loop means no final page can ever be reached from this entry point.",
            limitations=["Loop detection compares exact (normalised) URLs."],
            recommendation="Fix the redirect map."))

    if final is None:
        result.update(status="error", error_kind=(chain_error or {}).get("kind"),
                      error=(chain_error or {}).get("message", "No final response received"))
        result["findings"] = [f.to_dict() for f in findings]
        return result

    result["final"] = final
    result["timing"] = {"ttfb_ms": holder["ttfb_ms"], "total_ms": holder["total_ms"],
                        "note": "GET request; TTFB≈time to first byte of the FINAL response"}
    result["truncated"] = holder["truncated"]
    result["user_agent_sent"] = settings.user_agent
    result["head_vs_get_note"] = ("We use GET. A HEAD request is legal for servers to answer "
                                  "differently (headers, status, compression).")

    # Client-side navigation: meta refresh / JS location changes.
    if _JS_NAV_RE.search(holder["body"]):
        result["js_navigation"] = True
        findings.append(Finding(
            name="client_side_navigation", module="http", status=INFO,
            evidence="Final HTML contains a meta-refresh or JavaScript location change.",
            why="Browsers may navigate further even though the HTTP chain stopped here.",
            limitations=["Detected by pattern match on bounded HTML; not executed."],
            recommendation="Measure redirects with curl -I when comparing against a browser."))
    else:
        result["js_navigation"] = False

    # Explicit plain-HTTP probe (its own finding lives in security.py).
    if target.scheme == "https" and not target.is_ip_literal:
        result["http_probe"] = probe_plain_http(target, settings)
    else:
        result["http_probe"] = {
            "tested": False,
            "reason": ("Target itself is plain HTTP; the main chain above IS the HTTP evidence."
                       if target.scheme == "http"
                       else "IP-literal target: host-header redirects are not meaningful for the probe."),
        }

    result["html_excerpt"] = holder["body"][: config.MAX_HTML_EXCERPT].decode(
        (holder["response"].charset_encoding or "utf-8"), "replace") \
        if ("text/html" in final["content_type"] or not final["content_type"]) else None

    result["findings"] = [f.to_dict() for f in findings]
    return result


def probe_plain_http(target: TargetInfo, settings) -> dict:
    """Bounded, separate evidence for 'does http://… get upgraded to https?'."""
    url = (f"http://{target.idna_hostname}"
           f"{':' + str(target.port) if target.port else ''}/")
    probe_settings = type(settings)(
        **{**settings.__dict__, "max_redirects": config.PROBE_MAX_REDIRECTS})
    hops: list[dict] = []
    try:
        hops, holder, chain_error = follow_chain(url, probe_settings)
    except httpx.RequestError as exc:
        kind, msg = _classify(exc)
        return {"tested": True, "probe_url": url, "hops": hops,
                "ends_on_https": None, "error": f"{kind}: {msg}",
                "note": "Probe failure does NOT prove there is no redirect (port 80 may be closed on purpose)."}
    final_scheme = None
    if holder.get("response") is not None:
        # connection already released by follow_chain's client.close()
        final_scheme = holder["response"].url.scheme
    return {"tested": True, "probe_url": url,
            "hops": hops, "final_status": holder["response"].status_code if holder.get("response") else None,
            "ends_on_https": final_scheme == "https" if final_scheme else None,
            "chain_error": chain_error,
            "note": "Single request to '/'; other paths/hosts may redirect differently."}
