#!/usr/bin/env python3
"""
BountyTargetScout: Automated Bug Bounty Target Extraction & IDOR Screening Bot
=============================================================================
Extracts newly launched and updated VDP & Bounty programs across HackerOne,
Bugcrowd, and YesWeHack. Supports both Authenticated Mode (private invitations,
official APIs, deeper credential access) and Public Discovery Mode.

Features:
- Safe Anti-Ban Protection: Strict per-platform rate limiting (1.2s - 2.0s delays),
  automatic 429 Retry-After compliance, and an intelligent Circuit Breaker that
  trips immediately on 401/403 auth errors to protect researcher accounts from bans.
- Chronological Ranking: Ranks targets from freshest to oldest by launch/update time.
- 7-Point IDOR Screening: Evaluates each target against IDOR hunting prerequisites.
- Multi-Format Reports: Responsive dark-mode HTML dashboard & Markdown reports.
- Zero-Secret Architecture: Reads all API keys/tokens from .env.
"""

import os
import sys
import json
import re
import html
import time
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Attempt to load python-dotenv for local .env management
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
    else:
        load_dotenv()
except ImportError:
    pass

try:
    from openai import OpenAI
except ImportError:
    print("Error: openai package is required. Run: pip install openai")
    sys.exit(1)


# ==============================================================================
# Safe Rate Limiter & Anti-Ban Protection
# ==============================================================================

class SafeRateLimiter:
    """
    Guarantees strict rate limits per domain and protects accounts from being
    rate-limited or banned. Includes an automatic circuit breaker that trips
    if an authenticated endpoint returns 401/403, preventing brute-force locks.
    """
    def __init__(self):
        self.last_calls = {}
        # Strict anti-ban intervals for authenticated calls
        self.auth_intervals = {
            "api.hackerone.com": 1.2,
            "api.yeswehack.com": 1.2,
            "bugcrowd.com": 2.0,
        }
        # Polite intervals for public catalog / dump queries
        self.public_intervals = {
            "hackerone.com": 0.15,
            "api.yeswehack.com": 0.2,
            "bugcrowd.com": 0.25,
        }
        self.circuit_tripped = {
            "hackerone": False,
            "yeswehack": False,
            "bugcrowd": False,
        }

    def wait(self, url, is_authenticated=False):
        intervals = self.auth_intervals if is_authenticated else self.public_intervals
        domain = "other"
        for d in intervals:
            if d in url:
                domain = d
                break

        min_interval = intervals.get(domain, 0.1)
        now = time.time()
        last = self.last_calls.get(domain, 0)
        elapsed = now - last
        if elapsed < min_interval:
            sleep_duration = min_interval - elapsed
            time.sleep(sleep_duration)
        self.last_calls[domain] = time.time()

    def trip_circuit(self, platform, status_code, message=""):
        self.circuit_tripped[platform] = True
        print(f"\n[!] =================================================================")
        print(f"[!] [SECURITY GUARD] {platform.upper()} Authentication Tripped Circuit Breaker!")
        print(f"[!] Received HTTP {status_code} ({message}).")
        print(f"[!] Disabling authenticated requests for {platform} to prevent account lock.")
        print(f"[!] Falling back automatically to safe Public Discovery Mode.")
        print(f"[!] =================================================================\n")

    def is_tripped(self, platform):
        return self.circuit_tripped.get(platform, False)


RATE_LIMITER = SafeRateLimiter()


# ==============================================================================
# HTTP Client with Resilient Retry Adapter
# ==============================================================================

def create_resilient_session(retries=3, backoff_factor=0.5):
    """Creates a requests session with automatic retries for transient server errors."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "application/json, text/html, */*",
    })
    return session

GLOBAL_SESSION = create_resilient_session()


def safe_request(method, url, platform=None, is_auth=False, **kwargs):
    """
    Wrapper around requests that enforces rate limiting, respects Retry-After headers,
    and checks circuit breakers to prevent account suspension.
    """
    RATE_LIMITER.wait(url, is_authenticated=is_auth)
    timeout = kwargs.pop("timeout", 15)

    try:
        r = GLOBAL_SESSION.request(method, url, timeout=timeout, **kwargs)

        # Handle rate limiting (429) gracefully
        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            wait_time = int(retry_after) if retry_after and retry_after.isdigit() else 5
            wait_time = min(wait_time, 30)
            print(f"[!] Rate limited on {url}. Backing off for {wait_time}s...")
            time.sleep(wait_time)
            RATE_LIMITER.wait(url, is_authenticated=is_auth)
            r = GLOBAL_SESSION.request(method, url, timeout=timeout, **kwargs)

        # Handle Auth Errors (401/403)
        if r.status_code in [401, 403] and platform and is_auth and not RATE_LIMITER.is_tripped(platform):
            RATE_LIMITER.trip_circuit(platform, r.status_code, "Auth failure / Invalid credentials")

        return r
    except Exception as e:
        print(f"[!] Network error for {url}: {e}")
        return None


def fetch_json(url, headers=None, auth=None, platform=None):
    r = safe_request("GET", url, platform=platform, headers=headers, auth=auth)
    if r is not None and r.status_code == 200:
        try:
            return r.json()
        except Exception:
            pass
    return None


# ==============================================================================
# Configuration & Secret Management
# ==============================================================================

def load_config(args):
    """
    Loads LLM and bug bounty platform credentials from CLI arguments or .env.
    """
    api_key = args.api_key or os.getenv("LLM_API_KEY")
    base_url = args.base_url or os.getenv("LLM_BASE_URL") or "http://localhost:20128/v1"
    model = args.model or os.getenv("LLM_MODEL") or "MY-gemini-3.8-flash"

    # Local fallback to ~/.hermes/config.yaml for LLM if not set
    if not api_key:
        hermes_cfg_path = os.path.expanduser("~/.hermes/config.yaml")
        if os.path.exists(hermes_cfg_path):
            try:
                import yaml
                with open(hermes_cfg_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    api_key = (
                        cfg.get("providers", {}).get("omniroute", {}).get("api_key")
                        or cfg.get("model", {}).get("api_key")
                    )
            except Exception as e:
                print(f"[!] Warning reading ~/.hermes/config.yaml: {e}")

    # Platform authentication credentials
    use_auth = not args.no_auth
    auth_creds = {
        "h1_user": (args.h1_user or os.getenv("H1_API_IDENTIFIER")) if use_auth else None,
        "h1_token": (args.h1_token or os.getenv("H1_API_TOKEN")) if use_auth else None,
        "ywh_token": (args.ywh_token or os.getenv("YWH_API_TOKEN")) if use_auth else None,
        "bc_session": (args.bc_session or os.getenv("BUGCROWD_SESSION_TOKEN")) if use_auth else None,
    }

    return api_key, base_url, model, auth_creds


# ==============================================================================
# Helpers & Date Utilities
# ==============================================================================

def clean_html(raw_html):
    if not raw_html:
        return ""
    cleanr = re.compile(r"<.*?>")
    text = re.sub(cleanr, " ", raw_html)
    return " ".join(text.split()).strip()


def format_date(iso_str):
    """Formats an ISO timestamp or date string into YYYY-MM-DD or readable UTC format."""
    if not iso_str:
        return "N/A"
    try:
        s = str(iso_str).strip()
        if "T" in s:
            date_part, time_part = s.split("T")
            time_clean = time_part.split(".")[0].replace("Z", "").strip()
            if "+" in time_clean:
                time_clean = time_clean.split("+")[0]
            if len(time_clean) >= 5:
                return f"{date_part} ({time_clean[:5]} UTC)"
            return date_part
        return s[:10]
    except Exception:
        return str(iso_str)[:10]


def parse_timestamp_for_sort(date_str):
    """Parses date string into an integer YYYYMMDDHHMM for minute-level sorting precision."""
    if not date_str or date_str == "N/A":
        return 0
    clean = re.sub(r"[^\d]", "", str(date_str).split("(")[0].strip())
    if len(clean) >= 12:
        return int(clean[:12])
    elif len(clean) >= 8:
        return int(clean[:8] + "0000")
    return 0


# ==============================================================================
# Platform Fetching Modules (Authenticated & Public)
# ==============================================================================

def fetch_bugcrowd_targets_map():
    url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"
    data = fetch_json(url) or []
    mapping = {}
    for item in data:
        url_key = item.get("url", "").rstrip("/")
        name_key = item.get("name", "").strip().lower()
        if url_key:
            mapping[url_key] = item
        if name_key:
            mapping[name_key] = item
    return mapping


def fetch_bugcrowd_programs(count_per_type=2, auth_creds=None):
    print(f"[*] Querying Bugcrowd directory (target: {count_per_type} VDP & {count_per_type} Bounty)...")
    bc_map = fetch_bugcrowd_targets_map()
    session_token = auth_creds.get("bc_session") if auth_creds else None
    is_authenticated = bool(session_token and not RATE_LIMITER.is_tripped("bugcrowd"))

    headers = {}
    cookies = {}
    if is_authenticated:
        print("  [⚡] Bugcrowd Authenticated Mode Active (Session Cookie provided).")
        cookies["_crowdcontrol_session"] = session_token
        headers["Accept"] = "application/json"

    def process_category(category_name, is_bounty_target):
        url = f"https://bugcrowd.com/engagements.json?category={category_name}"
        r = safe_request("GET", url, platform="bugcrowd", is_auth=is_authenticated, headers=headers, cookies=cookies)
        data = r.json() if r and r.status_code == 200 else {}
        raw_engs = data.get("engagements", [])[:15]

        def get_engagement_details(en):
            brief_url = en.get("briefUrl", "")
            code = brief_url.strip("/").split("/")[-1]
            started_at, updated_at = "N/A", "N/A"
            try:
                cl_resp = safe_request("GET", f"https://bugcrowd.com/engagements/{code}/changelog.json", platform="bugcrowd", is_auth=is_authenticated, headers=headers, cookies=cookies)
                if cl_resp and cl_resp.status_code == 200:
                    logs = cl_resp.json().get("changelogs", [])
                    if logs:
                        updated_at = format_date(logs[0].get("publishedAt"))
                        started_at = format_date(logs[-1].get("publishedAt"))
            except Exception:
                pass

            sort_score = max(parse_timestamp_for_sort(updated_at), parse_timestamp_for_sort(started_at))
            return {"raw": en, "code": code, "started_at": started_at, "updated_at": updated_at, "sort_score": sort_score}

        with ThreadPoolExecutor(max_workers=4) as executor:
            candidates = list(executor.map(get_engagement_details, raw_engs))

        candidates.sort(key=lambda x: x["sort_score"], reverse=True)

        selected = []
        for item in candidates:
            if len(selected) >= count_per_type:
                break
            en = item["raw"]
            name = en.get("name")
            brief_url = en.get("briefUrl", "")
            full_url = f"https://bugcrowd.com{brief_url}"
            tagline = en.get("tagline", "")
            rs = en.get("rewardSummary") or {}

            # Detect private engagement vs public
            is_private = bool(en.get("accessStatus") == "invited" or en.get("confidential") or not brief_url.startswith("/engagements/"))

            # Deep brief description
            description = ""
            try:
                page_resp = safe_request("GET", full_url, platform="bugcrowd", is_auth=is_authenticated, headers=headers, cookies=cookies)
                if page_resp and page_resp.status_code == 200:
                    idx = page_resp.text.find("&quot;earlyFetchProps&quot;:")
                    if idx != -1:
                        sub = html.unescape(page_resp.text[idx + len("&quot;earlyFetchProps&quot;:") :])
                        brace_count, end = 0, 0
                        for i, c in enumerate(sub):
                            if c == "{":
                                brace_count += 1
                            elif c == "}":
                                brace_count -= 1
                                if brace_count == 0:
                                    end = i + 1
                                    break
                        if end > 0:
                            props = json.loads(sub[:end])
                            raw_desc = props.get("description", "")
                            description = clean_html(raw_desc)
            except Exception:
                pass

            extra = bc_map.get(full_url.rstrip("/")) or bc_map.get(name.strip().lower()) or {}
            targets = extra.get("targets", {})
            reward_str = rs.get("summary") or ("Cash Bounty" if is_bounty_target else "Points Only / None")

            prog_info = {
                "name": name,
                "url": full_url,
                "platform": "Bugcrowd",
                "type": "Bounty" if is_bounty_target else "VDP",
                "visibility": "Private" if is_private else "Public",
                "tagline": tagline,
                "reward": reward_str,
                "launched_at": item["started_at"],
                "last_updated_at": item["updated_at"],
                "description": description or tagline,
                "targets": targets,
            }
            selected.append(prog_info)
            vis_icon = "🔒" if is_private else "🌐"
            type_label = "Bounty" if is_bounty_target else "VDP"
            print(f"  [+] Bugcrowd {type_label}: {name} [{vis_icon} {prog_info['visibility']}] (Launched: {item['started_at']} | Updated: {item['updated_at']})")

        return selected

    bounty = process_category("bug_bounty", True)
    vdp = process_category("vdp", False)

    return vdp, bounty


def fetch_yeswehack_programs(count_per_type=2, auth_creds=None):
    print(f"[*] Querying YesWeHack directory (target: {count_per_type} VDP & {count_per_type} Bounty)...")
    vdp, bounty = [], []
    ywh_token = auth_creds.get("ywh_token") if auth_creds else None
    is_authenticated = bool(ywh_token and not RATE_LIMITER.is_tripped("yeswehack"))

    headers = {"Accept": "application/json"}
    if is_authenticated:
        print("  [⚡] YesWeHack Authenticated Mode Active (Bearer Token provided).")
        headers["Authorization"] = f"Bearer {ywh_token}"

    # In authenticated mode, query private programs first to capture exclusive invitations
    types_to_query = ["private", "public"] if is_authenticated else ["public"]

    for ptype in types_to_query:
        if len(bounty) >= count_per_type and len(vdp) >= count_per_type:
            break

        page = 1
        while (len(vdp) < count_per_type or len(bounty) < count_per_type) and page <= 3:
            url = f"https://api.yeswehack.com/programs?sort=public_date&direction=desc&type={ptype}&page={page}"
            r = safe_request("GET", url, platform="yeswehack", is_auth=(ptype == "private" or is_authenticated), headers=headers)
            if r is None or r.status_code != 200:
                break
            data = r.json()
            items = data.get("items", []) if data else []
            if not items:
                break

            for it in items:
                name = it.get("title")
                slug = it.get("slug")
                full_url = f"https://yeswehack.com/programs/{slug}"
                is_vdp = bool(it.get("vdp"))
                is_bounty = bool(it.get("bounty"))
                is_private = (ptype == "private") or bool(it.get("private")) or not bool(it.get("public"))

                if is_bounty and len(bounty) >= count_per_type:
                    continue
                if (is_vdp or not is_bounty) and len(vdp) >= count_per_type:
                    continue

                # Fetch detailed program briefing
                detail_resp = safe_request("GET", f"https://api.yeswehack.com/programs/{slug}", platform="yeswehack", is_auth=is_authenticated, headers=headers)
                detail = detail_resp.json() if detail_resp and detail_resp.status_code == 200 else {}
                rules_text = detail.get("rules", "") or clean_html(detail.get("rules_html", ""))
                scopes = detail.get("scopes", [])
                out_of_scope = detail.get("out_of_scope", [])
                account_access = detail.get("account_access", "") or clean_html(detail.get("account_access_html", ""))
                min_b = detail.get("bounty_reward_min")
                max_b = detail.get("bounty_reward_max")
                reward_str = f"€{min_b} - €{max_b}" if (min_b or max_b) else ("VDP / Swag" if not is_bounty else "Bounty")

                updated_at = format_date(detail.get("last_update_at") or it.get("last_update_at"))
                started_at = format_date(detail.get("public_date") or it.get("public_date"))
                if started_at == "N/A":
                    started_at = updated_at

                formatted_in = []
                for s in scopes:
                    if isinstance(s, dict):
                        formatted_in.append({"target": s.get("scope") or s.get("target"), "type": s.get("scope_type")})
                    elif isinstance(s, str):
                        formatted_in.append({"target": s, "type": "target"})

                formatted_out = []
                for s in out_of_scope:
                    if isinstance(s, dict):
                        formatted_out.append({"target": s.get("scope") or s.get("target"), "type": s.get("scope_type")})
                    elif isinstance(s, str):
                        formatted_out.append({"target": s, "type": "out_of_scope"})

                prog_info = {
                    "name": name,
                    "url": full_url,
                    "platform": "YesWeHack",
                    "type": "Bounty" if is_bounty else "VDP",
                    "visibility": "Private" if is_private else "Public",
                    "reward": reward_str,
                    "launched_at": started_at,
                    "last_updated_at": updated_at,
                    "description": rules_text[:4000],
                    "account_access": account_access,
                    "targets": {
                        "in_scope": formatted_in,
                        "out_of_scope": formatted_out,
                    },
                }

                vis_icon = "🔒" if is_private else "🌐"
                if is_bounty and len(bounty) < count_per_type:
                    bounty.append(prog_info)
                    print(f"  [+] YesWeHack Bounty: {name} [{vis_icon} {prog_info['visibility']}] (Launched: {started_at} | Updated: {updated_at})")
                elif (is_vdp or not is_bounty) and len(vdp) < count_per_type:
                    vdp.append(prog_info)
                    print(f"  [+] YesWeHack VDP: {name} [{vis_icon} {prog_info['visibility']}] (Launched: {started_at} | Updated: {updated_at})")

                if len(bounty) >= count_per_type and len(vdp) >= count_per_type:
                    break

            page += 1

    return vdp, bounty


def fetch_h1_dates_batch(handles):
    """Queries HackerOne GraphQL API in parallel to retrieve launch and update timestamps."""
    query = """
    query TeamDates($handle: String!) {
      team(handle: $handle) {
        handle
        started_accepting_at
        launched_at
        last_updated_at
      }
    }
    """
    results = {}

    def fetch_one(handle):
        try:
            r = safe_request("POST", "https://hackerone.com/graphql", platform="hackerone", json={"query": query, "variables": {"handle": handle}})
            if r and r.status_code == 200:
                t = r.json().get("data", {}).get("team") or {}
                started = t.get("launched_at") or t.get("started_accepting_at")
                updated = t.get("last_updated_at") or t.get("launched_at") or t.get("started_accepting_at")
                return handle, format_date(started), format_date(updated)
        except Exception:
            pass
        return handle, "N/A", "N/A"

    with ThreadPoolExecutor(max_workers=5) as executor:
        for handle, started, updated in executor.map(fetch_one, handles):
            results[handle] = (started, updated)

    return results


def fetch_hackerone_programs_authenticated(h1_user, h1_token, count_per_type=2):
    """
    Fetches accessible programs via the official HackerOne Hacker REST API:
    GET https://api.hackerone.com/v1/hackers/me/programs
    Bypasses Cloudflare protections and returns authentic private invitations.
    """
    print(f"[*] Querying HackerOne Official API (me/programs)...")
    url = "https://api.hackerone.com/v1/hackers/me/programs"
    auth = (h1_user, h1_token)
    r = safe_request("GET", url, platform="hackerone", is_auth=True, auth=auth)
    if not r or r.status_code != 200:
        return [], []

    data = r.json().get("data", [])
    vdp, bounty = [], []

    for item in data:
        attrs = item.get("attributes", {})
        handle = attrs.get("handle")
        name = attrs.get("name")
        offers_bounties = bool(attrs.get("offers_bounties"))
        state = attrs.get("state", "")
        is_private = state != "public_mode"
        started_at = format_date(attrs.get("started_accepting_at"))

        if offers_bounties and len(bounty) >= count_per_type:
            continue
        if not offers_bounties and len(vdp) >= count_per_type:
            continue

        # Fetch in-scope structured targets
        scopes_url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
        s_resp = safe_request("GET", scopes_url, platform="hackerone", is_auth=True, auth=auth)
        in_scope = []
        if s_resp and s_resp.status_code == 200:
            for sc in s_resp.json().get("data", []):
                s_attr = sc.get("attributes", {})
                if s_attr.get("eligible_for_submission"):
                    in_scope.append({
                        "target": s_attr.get("asset_identifier"),
                        "type": s_attr.get("asset_type"),
                    })

        prog_info = {
            "name": name,
            "url": f"https://hackerone.com/{handle}",
            "platform": "HackerOne",
            "type": "Bounty" if offers_bounties else "VDP",
            "visibility": "Private" if is_private else "Public",
            "reward": "Cash Bounty" if offers_bounties else "VDP (Reputation/Swag)",
            "launched_at": started_at,
            "last_updated_at": started_at,
            "description": f"HackerOne Program: {name} (Submission State: {attrs.get('submission_state')})",
            "targets": {"in_scope": in_scope, "out_of_scope": []},
        }

        vis_icon = "🔒" if is_private else "🌐"
        if offers_bounties and len(bounty) < count_per_type:
            bounty.append(prog_info)
            print(f"  [+] HackerOne Bounty: {name} [{vis_icon} {prog_info['visibility']}] (Launched: {started_at})")
        elif not offers_bounties and len(vdp) < count_per_type:
            vdp.append(prog_info)
            print(f"  [+] HackerOne VDP: {name} [{vis_icon} {prog_info['visibility']}] (Launched: {started_at})")

        if len(bounty) >= count_per_type and len(vdp) >= count_per_type:
            break

    return vdp, bounty


def fetch_hackerone_programs(count_per_type=2, auth_creds=None):
    h1_user = auth_creds.get("h1_user") if auth_creds else None
    h1_token = auth_creds.get("h1_token") if auth_creds else None
    is_authenticated = bool(h1_user and h1_token and not RATE_LIMITER.is_tripped("hackerone"))

    vdp, bounty = [], []
    if is_authenticated:
        print("  [⚡] HackerOne Authenticated Mode Active (Official Hacker API).")
        vdp, bounty = fetch_hackerone_programs_authenticated(h1_user, h1_token, count_per_type=count_per_type)

    # If count not met or public fallback, supplement from public aggregator
    if len(vdp) < count_per_type or len(bounty) < count_per_type:
        needed_vdp = count_per_type - len(vdp)
        needed_bounty = count_per_type - len(bounty)
        print(f"[*] Querying HackerOne directory (need {needed_vdp} VDP & {needed_bounty} Bounty)...")
        url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
        data = fetch_json(url) or []

        candidates = data[:40]
        handles = [en.get("handle") or en.get("url", "").rstrip("/").split("/")[-1] for en in candidates if en.get("handle") or en.get("url")]

        dates_map = fetch_h1_dates_batch(handles)

        parsed_candidates = []
        for en in candidates:
            h = en.get("handle") or en.get("url", "").rstrip("/").split("/")[-1]
            started_at, updated_at = dates_map.get(h, ("N/A", "N/A"))
            sort_score = max(parse_timestamp_for_sort(started_at), parse_timestamp_for_sort(updated_at))
            parsed_candidates.append({
                "raw": en,
                "handle": h,
                "started_at": started_at,
                "updated_at": updated_at,
                "sort_score": sort_score,
            })

        parsed_candidates.sort(key=lambda x: x["sort_score"], reverse=True)

        for item in parsed_candidates:
            en = item["raw"]
            name = en.get("name")
            prog_url = en.get("url")
            is_bounty = bool(en.get("offers_bounties"))

            if is_bounty and len(bounty) >= count_per_type:
                continue
            if not is_bounty and len(vdp) >= count_per_type:
                continue

            resp_eff = en.get("response_efficiency_percentage")
            first_resp = en.get("average_time_to_first_program_response")
            resolved_time = en.get("average_time_to_report_resolved")
            targets = en.get("targets", {})

            stats_str = (
                f"Response Efficiency: {resp_eff}% | "
                f"Avg First Response: {first_resp} hrs | "
                f"Avg Resolution Time: {resolved_time} hrs"
            )

            prog_info = {
                "name": name,
                "url": prog_url,
                "platform": "HackerOne",
                "type": "Bounty" if is_bounty else "VDP",
                "visibility": "Public",
                "reward": "Cash Bounty" if is_bounty else "VDP (Reputation/Swag)",
                "launched_at": item["started_at"],
                "last_updated_at": item["updated_at"],
                "stats": stats_str,
                "description": f"HackerOne Program: {name}. Health stats: {stats_str}",
                "targets": targets,
            }

            if is_bounty and len(bounty) < count_per_type:
                bounty.append(prog_info)
                print(f"  [+] HackerOne Bounty: {name} [🌐 Public] (Launched: {item['started_at']} | Updated: {item['updated_at']})")
            elif not is_bounty and len(vdp) < count_per_type:
                vdp.append(prog_info)
                print(f"  [+] HackerOne VDP: {name} [🌐 Public] (Launched: {item['started_at']} | Updated: {item['updated_at']})")

            if len(bounty) >= count_per_type and len(vdp) >= count_per_type:
                break

    return vdp, bounty


# ==============================================================================
# LLM Evaluation Engine
# ==============================================================================

def evaluate_program_with_llm(client, model, prog):
    """
    Evaluates the program against the 7 IDOR criteria using Omniroute / LLM.
    Leaves checkbox [ ] if unable to confirm or information is lacking.
    """
    in_scope_summary = []
    in_scope = prog.get("targets", {}).get("in_scope", [])
    for s in in_scope[:8]:
        target = s.get("target") or s.get("asset_identifier") or s.get("uri") or ""
        stype = s.get("type") or s.get("asset_type") or ""
        in_scope_summary.append(f"{target} ({stype})")

    out_scope_summary = []
    out_scope = prog.get("targets", {}).get("out_of_scope", [])
    for s in out_scope[:6]:
        target = s.get("target") or s.get("asset_identifier") or ""
        out_scope_summary.append(target)

    context_text = f"""
Platform: {prog.get('platform')}
Program Name: {prog.get('name')}
Program Type: {prog.get('type')} ({prog.get('reward')})
Visibility: {prog.get('visibility', 'Public')}
URL: {prog.get('url')}
Launched / Started Date: {prog.get('launched_at', 'N/A')}
Last Updated Date: {prog.get('last_updated_at', 'N/A')}
Health Stats: {prog.get('stats', 'N/A')}
Account/Registration Info: {prog.get('account_access', 'N/A')}
Policy / Description:
{prog.get('description', '')[:2500]}

In-Scope Targets ({len(in_scope)} total):
{', '.join(in_scope_summary) if in_scope_summary else 'No granular target list provided'}

Out-Of-Scope Assets:
{', '.join(out_scope_summary) if out_scope_summary else 'Standard platform out-of-scope policies'}
"""

    prompt = f"""You are an elite Bug Bounty hunter screening targets specifically for IDOR (Insecure Direct Object Reference) and broken object-level authorization vulnerabilities.

Analyze the program details below and evaluate each of the 7 criteria.

CRITICAL INSTRUCTIONS:
- For any criterion where the policy/metadata does NOT explicitly provide sufficient proof, you MUST leave the checkbox empty: `- [ ]`.
- Only check `- [x]` if the criterion is confirmed by the provided data.
- For each item, provide a single, punchy 1-sentence note justifying your finding.
- If information is missing or unclear, state: "Requires manual review (details not specified in policy)".

Evaluate these 7 criteria:
1. Login and user accounts: Authenticated SaaS tools, marketplaces, booking platforms, fintech, or e-commerce apps with login/auth.
2. Free, open self-registration: Ability to create two or more test accounts freely without KYC, enterprise vetting, or paid tiers.
3. Multi-user features: Presence of teams, organizations, roles, invites, sharing, file uploads, billing, or collaboration features.
4. Business logic in scope: Business logic and authorization/access control flaws are in scope and not listed in out-of-scope exclusions.
5. A mid-size or newer program: Target is a specialized, mid-sized or newer program rather than a massive legacy tech monopoly (e.g., Google, Apple, Microsoft, Meta). Consider the Launched Date and Last Updated Date.
6. Healthy program stats: Check metrics when available (e.g. response efficiency >= 80% and first response <= 48h on HackerOne indicates healthy stats). If metrics are provided and good, check [x]; if stats are N/A or slow, leave [ ].
7. An API or mobile app in scope: REST, GraphQL APIs, Swagger docs, or iOS/Android mobile apps explicitly in scope.

Program Context:
{context_text}

OUTPUT FORMAT:
Output ONLY the 7 markdown checkboxes in this format:
- [x] or [ ] **Criterion Name**: <1-sentence rationale>
"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            timeout=60,
        )
        content = response.choices[0].message.content.strip()
        return content
    except Exception as e:
        print(f"[!] LLM evaluation failed for {prog.get('name')}: {e}")
        return (
            "- [ ] **Login and user accounts**: LLM evaluation error - requires manual review.\n"
            "- [ ] **Free, open self-registration**: LLM evaluation error - requires manual review.\n"
            "- [ ] **Multi-user features**: LLM evaluation error - requires manual review.\n"
            "- [ ] **Business logic in scope**: LLM evaluation error - requires manual review.\n"
            "- [ ] **A mid-size or newer program**: LLM evaluation error - requires manual review.\n"
            "- [ ] **Healthy program stats**: LLM evaluation error - requires manual review.\n"
            "- [ ] **An API or mobile app in scope**: LLM evaluation error - requires manual review."
        )


def calculate_score(checklist_text):
    """Calculates number of checked criteria out of 7."""
    checked = len(re.findall(r"-\s*\[x\]", checklist_text, re.IGNORECASE))
    return checked


# ==============================================================================
# Markdown Report Generator (Chronologically Ranked)
# ==============================================================================

def generate_markdown_report(programs_with_evals, output_path, model_name):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_progs = len(programs_with_evals)

    md = []
    md.append("# 🎯 Bug Bounty IDOR Target Reconnaissance Report")
    md.append(f"*Generated on: `{now_str}`* | *Model: `{model_name}`* | *Total Programs: `{total_progs}`*\n")
    md.append(
        "> **Methodology:** Targets are ranked **chronologically by launch & last update recency**. "
        "Each program is screened against 7 core IDOR hunting prerequisites. Criteria lacking explicit policy confirmation "
        "are left unchecked `[ ]` for manual triage.\n"
    )

    # Executive Summary Table (Ranked)
    md.append("## 📊 Executive Target Matrix (Ranked by Recency)\n")
    md.append("| Rank | Platform | Program | Type | Access | Reward | Launched | Last Updated | IDOR Score | Quick Link |")
    md.append("|:---:|---|---|---|:---:|---|:---:|:---:|:---:|:---:|")

    for idx, item in enumerate(programs_with_evals, 1):
        p = item["prog"]
        score = item["score"]
        score_badge = f"**{score}/7**"
        if score >= 5:
            score_badge = f"🟢 **{score}/7 (High)**"
        elif score >= 3:
            score_badge = f"🟡 **{score}/7 (Med)**"
        else:
            score_badge = f"⚪ **{score}/7 (Low)**"

        vis_badge = "🔒 `Private`" if p.get("visibility") == "Private" else "🌐 `Public`"

        md.append(
            f"| **#{idx}** | **{p['platform']}** | {p['name']} | `{p['type']}` | {vis_badge} | {p['reward']} | `{p.get('launched_at', 'N/A')}` | `{p.get('last_updated_at', 'N/A')}` | {score_badge} | [View Policy]({p['url']}) |"
        )
    md.append("\n---\n")

    # Detailed Program Cards
    md.append("## 🔍 Detailed Program Evaluations\n")
    for idx, item in enumerate(programs_with_evals, 1):
        p = item["prog"]
        eval_text = item["eval"]
        score = item["score"]

        icon = "🛡️" if p["platform"] == "HackerOne" else ("🐞" if p["platform"] == "Bugcrowd" else "⚔️")
        vis_tag = "🔒 [PRIVATE INVITATION]" if p.get("visibility") == "Private" else "🌐 [PUBLIC PROGRAM]"

        md.append(f"### #{idx}. {icon} {p['name']} (`{p['type']}` - {p['platform']}) {vis_tag}\n")
        md.append(f"- **Program URL:** [{p['url']}]({p['url']})")
        md.append(f"- **Access Visibility:** `{p.get('visibility', 'Public')}`")
        md.append(f"- **Reward:** `{p['reward']}`")
        md.append(f"- **Launched / Started:** `{p.get('launched_at', 'N/A')}`")
        md.append(f"- **Last Updated:** `{p.get('last_updated_at', 'N/A')}`")
        if p.get("stats"):
            md.append(f"- **Platform Stats:** `{p['stats']}`")
        if p.get("account_access"):
            md.append(f"- **Credentials/Access:** {p['account_access']}")

        md.append(f"\n#### 🎯 IDOR Readiness Checklist (Score: {score}/7)\n")
        md.append(eval_text)
        md.append("\n")

        # Collapsible Scope Details
        in_scope = p.get("targets", {}).get("in_scope", [])
        if in_scope:
            md.append("<details>")
            md.append("<summary><b>📂 Target Scope Details</b></summary>\n")
            md.append("```yaml")
            for t in in_scope[:15]:
                identifier = t.get("target") or t.get("asset_identifier") or t.get("uri")
                ttype = t.get("type") or t.get("asset_type") or "target"
                md.append(f"- {identifier} ({ttype})")
            if len(in_scope) > 15:
                md.append(f"# ... and {len(in_scope) - 15} more in-scope targets")
            md.append("```")
            md.append("</details>\n")

        md.append("---\n")

    # Recommendations
    sorted_by_score = sorted(programs_with_evals, key=lambda x: (x["prog"].get("visibility") == "Private", x["score"]), reverse=True)
    best_progs = [x for x in sorted_by_score if x["score"] >= 3]

    md.append("## 🏆 Recommended Hunting Order (Priority: Private Invites & High IDOR Viability)\n")
    if best_progs:
        for i, b in enumerate(best_progs[:5], 1):
            p = b["prog"]
            vis_label = "🔒 PRIVATE" if p.get("visibility") == "Private" else "🌐 PUBLIC"
            md.append(
                f"{i}. **[{p['platform']}] {p['name']}** (`{p['type']}` - {vis_label}) - Score **{b['score']}/7** | Launched: `{p.get('launched_at')}` ([Open]({p['url']}))"
            )
    else:
        md.append("*Review the unconfirmed criteria `[ ]` above to manually select targets.*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    return output_path


# ==============================================================================
# Modern Responsive HTML Report Generator
# ==============================================================================

def generate_html_report(programs_with_evals, output_path, model_name):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_progs = len(programs_with_evals)
    high_score_count = sum(1 for p in programs_with_evals if p["score"] >= 4)
    private_count = sum(1 for p in programs_with_evals if p["prog"].get("visibility") == "Private")
    public_count = total_progs - private_count
    bounty_count = sum(1 for p in programs_with_evals if p["prog"]["type"] == "Bounty")
    vdp_count = sum(1 for p in programs_with_evals if p["prog"]["type"] == "VDP")

    # Build matrix table rows
    table_rows = []
    for idx, item in enumerate(programs_with_evals, 1):
        p = item["prog"]
        score = item["score"]
        score_class = "score-high" if score >= 5 else ("score-med" if score >= 3 else "score-low")
        platform_class = f"badge-{p['platform'].lower()}\""
        type_class = "badge-bounty" if p["type"] == "Bounty" else "badge-vdp"
        vis_class = "badge-private" if p.get("visibility") == "Private" else "badge-public"
        vis_icon = "🔒" if p.get("visibility") == "Private" else "🌐"

        table_rows.append(f"""
        <tr data-platform="{p['platform'].lower()}" data-type="{p['type'].lower()}" data-visibility="{p.get('visibility', 'public').lower()}">
            <td class="text-center"><strong>#{idx}</strong></td>
            <td><span class="badge {platform_class}>{p['platform']}</span></td>
            <td><a href="#card-{idx}" class="program-link">{p['name']}</a></td>
            <td><span class="badge {type_class}">{p['type']}</span></td>
            <td><span class="badge {vis_class}">{vis_icon} {p.get('visibility', 'Public')}</span></td>
            <td><code>{p['reward']}</code></td>
            <td class="text-muted"><small>{p.get('launched_at', 'N/A')}</small></td>
            <td class="text-muted"><small>{p.get('last_updated_at', 'N/A')}</small></td>
            <td class="text-center"><span class="score-pill {score_class}">{score}/7</span></td>
            <td class="text-center"><a href="{p['url']}" target="_blank" class="btn-external">Policy ↗</a></td>
        </tr>
        """)

    # Build detailed program cards
    cards_html = []
    for idx, item in enumerate(programs_with_evals, 1):
        p = item["prog"]
        eval_text = item["eval"]
        score = item["score"]
        platform_class = f"badge-{p['platform'].lower()}"
        type_class = "badge-bounty" if p["type"] == "Bounty" else "badge-vdp"
        vis_class = "badge-private" if p.get("visibility") == "Private" else "badge-public"
        vis_icon = "🔒" if p.get("visibility") == "Private" else "🌐"
        score_class = "score-high" if score >= 5 else ("score-med" if score >= 3 else "score-low")

        checklist_items = []
        for line in eval_text.splitlines():
            line = line.strip()
            if not line:
                continue
            is_checked = line.startswith("- [x]") or line.startswith("* [x]")
            is_empty = line.startswith("- [ ]") or line.startswith("* [ ]")
            if is_checked or is_empty:
                content = re.sub(r"^[-*]\s*\[[ xX]\]\s*", "", line)
                content = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", content)
                icon = '<span class="check-icon success">✓</span>' if is_checked else '<span class="check-icon pending">○</span>'
                item_class = "item-checked" if is_checked else "item-pending"
                checklist_items.append(f'<li class="{item_class}">{icon} <div class="item-text">{content}</div></li>')

        checklist_html = "\n".join(checklist_items)

        in_scope = p.get("targets", {}).get("in_scope", [])
        scopes_html = ""
        if in_scope:
            scope_lines = []
            for t in in_scope[:20]:
                identifier = t.get("target") or t.get("asset_identifier") or t.get("uri")
                ttype = t.get("type") or t.get("asset_type") or "target"
                scope_lines.append(f"<li><span class=\"target-name\">{identifier}</span> <span class=\"target-type\">({ttype})</span></li>")
            if len(in_scope) > 20:
                scope_lines.append(f"<li class=\"text-muted\">... and {len(in_scope) - 20} more in-scope targets</li>")

            scopes_html = f"""
            <details class="scopes-accordion">
                <summary>Target Scope Assets ({len(in_scope)} items)</summary>
                <ul class="scope-list">
                    {''.join(scope_lines)}
                </ul>
            </details>
            """

        stats_html = f'<div class="meta-item"><strong>Platform Health:</strong> {p.get("stats")}</div>' if p.get("stats") else ""
        access_html = f'<div class="meta-item"><strong>Registration / Access:</strong> {p.get("account_access")}</div>' if p.get("account_access") else ""

        cards_html.append(f"""
        <div class="card" id="card-{idx}" data-platform="{p['platform'].lower()}" data-type="{p['type'].lower()}" data-visibility="{p.get('visibility', 'public').lower()}">
            <div class="card-header">
                <div class="card-title-group">
                    <span class="card-rank">#{idx}</span>
                    <h3 class="card-title">{p['name']}</h3>
                    <span class="badge {platform_class}">{p['platform']}</span>
                    <span class="badge {type_class}">{p['type']}</span>
                    <span class="badge {vis_class}">{vis_icon} {p.get('visibility', 'Public')}</span>
                </div>
                <div class="card-score-pill">
                    <span class="score-pill {score_class}">{score}/7 IDOR Viability</span>
                </div>
            </div>

            <div class="card-meta-grid">
                <div class="meta-item"><strong>Access:</strong> {vis_icon} {p.get('visibility', 'Public')}</div>
                <div class="meta-item"><strong>Reward:</strong> <code>{p['reward']}</code></div>
                <div class="meta-item"><strong>Launched:</strong> {p.get('launched_at', 'N/A')}</div>
                <div class="meta-item"><strong>Last Updated:</strong> {p.get('last_updated_at', 'N/A')}</div>
                <div class="meta-item"><strong>Program Link:</strong> <a href="{p['url']}" target="_blank">{p['url']}</a></div>
            </div>

            {stats_html}
            {access_html}

            <div class="checklist-container">
                <h4>7-Point IDOR Screening Checklist:</h4>
                <ul class="checklist">
                    {checklist_html}
                </ul>
            </div>

            {scopes_html}
        </div>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty IDOR Target Reconnaissance Report</title>
    <style>
        :root {{
            --bg-main: #0b0f19;
            --bg-card: #151d2f;
            --bg-hover: #1e293b;
            --border-color: #243049;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.2);
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.2);
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #a855f7;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: var(--font-family);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }}
        h1 {{
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header-meta {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.2rem;
            text-align: center;
        }}
        .stat-val {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 0.2rem;
        }}
        .stat-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .filter-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            background-color: var(--bg-card);
            padding: 0.8rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .filter-btn {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 0.4rem 0.9rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background-color: var(--primary);
            color: #000;
            border-color: var(--primary);
            font-weight: 600;
        }}

        .table-responsive {{
            overflow-x: auto;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 3rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(30, 41, 59, 0.5);
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        tr:hover td {{
            background-color: var(--bg-hover);
        }}
        .text-center {{ text-align: center; }}
        .text-muted {{ color: var(--text-muted); }}

        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-hackerone {{ background: rgba(234, 88, 12, 0.2); color: #fb923c; border: 1px solid rgba(234, 88, 12, 0.4); }}
        .badge-bugcrowd {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-yeswehack {{ background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }}
        .badge-bounty {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge-vdp {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }}
        .badge-private {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
        .badge-public {{ background: rgba(56, 189, 248, 0.15); color: #38bdf8; }}

        .score-pill {{
            display: inline-block;
            padding: 0.25rem 0.65rem;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.8rem;
        }}
        .score-high {{ background: var(--success-glow); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.4); }}
        .score-med {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .score-low {{ background: rgba(148, 163, 184, 0.15); color: #94a3b8; }}

        .program-link {{
            color: var(--text-main);
            text-decoration: none;
            font-weight: 600;
        }}
        .program-link:hover {{ color: var(--primary); }}
        .btn-external {{
            color: var(--primary);
            text-decoration: none;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            border: 1px solid rgba(56, 189, 248, 0.3);
            font-size: 0.75rem;
        }}
        .btn-external:hover {{ background-color: var(--primary-glow); }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: border-color 0.2s;
        }}
        .card:hover {{
            border-color: rgba(56, 189, 248, 0.5);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.8rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.8rem;
        }}
        .card-title-group {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            flex-wrap: wrap;
        }}
        .card-rank {{
            font-size: 1.2rem;
            font-weight: 800;
            color: var(--primary);
        }}
        .card-title {{
            font-size: 1.3rem;
            font-weight: 700;
        }}
        .card-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0.8rem;
            font-size: 0.85rem;
            background-color: rgba(11, 15, 25, 0.4);
            padding: 0.8rem 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }}
        .meta-item a {{ color: var(--primary); text-decoration: none; }}
        .checklist-container {{
            margin: 1.2rem 0;
        }}
        .checklist-container h4 {{
            font-size: 0.95rem;
            margin-bottom: 0.6rem;
            color: var(--primary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .checklist {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .checklist li {{
            display: flex;
            align-items: flex-start;
            gap: 0.6rem;
            font-size: 0.9rem;
            padding: 0.4rem 0.6rem;
            border-radius: 6px;
            background-color: rgba(30, 41, 59, 0.3);
        }}
        .check-icon {{
            font-weight: 800;
            font-size: 1rem;
            line-height: 1.2;
        }}
        .check-icon.success {{ color: var(--success); }}
        .check-icon.pending {{ color: var(--text-muted); opacity: 0.6; }}
        .item-checked {{ border-left: 3px solid var(--success); }}
        .item-pending {{ border-left: 3px solid var(--border-color); opacity: 0.85; }}

        .scopes-accordion {{
            margin-top: 1rem;
            background-color: rgba(11, 15, 25, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.5rem 0.8rem;
        }}
        .scopes-accordion summary {{
            cursor: pointer;
            font-weight: 600;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .scopes-accordion summary:hover {{ color: var(--primary); }}
        .scope-list {{
            margin-top: 0.6rem;
            padding-left: 1.2rem;
            font-family: monospace;
            font-size: 0.8rem;
            color: #cbd5e1;
        }}
        .target-type {{ color: var(--text-muted); }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        @media (max-width: 768px) {{
            .card-header {{ flex-direction: column; align-items: flex-start; }}
            .card-meta-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 Bug Bounty IDOR Target Reconnaissance</h1>
            <p class="header-meta">Generated on <strong>{now_str}</strong> • Evaluated with <strong>{model_name}</strong> • Filtered for IDOR Hunting</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val">{total_progs}</div>
                <div class="stat-label">Total Programs</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{high_score_count}</div>
                <div class="stat-label">High IDOR Viability (≥4/7)</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{private_count} / {public_count}</div>
                <div class="stat-label">Private / Public</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{bounty_count} / {vdp_count}</div>
                <div class="stat-label">Bounties / VDPs</div>
            </div>
        </div>

        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterTargets('all', event)">All Programs ({total_progs})</button>
            <button class="filter-btn" onclick="filterTargets('private', event)">🔒 Private Only ({private_count})</button>
            <button class="filter-btn" onclick="filterTargets('public', event)">🌐 Public Only ({public_count})</button>
            <button class="filter-btn" onclick="filterTargets('hackerone', event)">HackerOne</button>
            <button class="filter-btn" onclick="filterTargets('bugcrowd', event)">Bugcrowd</button>
            <button class="filter-btn" onclick="filterTargets('yeswehack', event)">YesWeHack</button>
            <button class="filter-btn" onclick="filterTargets('bounty', event)">Bounties Only</button>
            <button class="filter-btn" onclick="filterTargets('vdp', event)">VDP Only</button>
        </div>

        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th class="text-center">Rank</th>
                        <th>Platform</th>
                        <th>Program</th>
                        <th>Type</th>
                        <th>Access</th>
                        <th>Reward</th>
                        <th>Launched</th>
                        <th>Last Updated</th>
                        <th class="text-center">IDOR Score</th>
                        <th class="text-center">Action</th>
                    </tr>
                </thead>
                <tbody id="matrix-tbody">
                    {''.join(table_rows)}
                </tbody>
            </table>
        </div>

        <section id="cards-section">
            <h2 style="margin-bottom: 1.2rem; font-size: 1.5rem; font-weight: 700;">Detailed Program Findings</h2>
            {''.join(cards_html)}
        </section>

        <footer>
            <p>BountyTargetScout • Automated Reconnaissance & IDOR Screening</p>
        </footer>
    </div>

    <script>
        function filterTargets(filter, evt) {{
            const ev = evt || window.event;
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            if (ev && ev.target) {{
                ev.target.classList.add('active');
            }}

            const rows = document.querySelectorAll('#matrix-tbody tr');
            const cards = document.querySelectorAll('.card');

            rows.forEach(row => {{
                const platform = row.getAttribute('data-platform');
                const type = row.getAttribute('data-type');
                const visibility = row.getAttribute('data-visibility');
                if (filter === 'all' || platform === filter || type === filter || visibility === filter) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});

            cards.forEach(card => {{
                const platform = card.getAttribute('data-platform');
                const type = card.getAttribute('data-type');
                const visibility = card.getAttribute('data-visibility');
                if (filter === 'all' || platform === filter || type === filter || visibility === filter) {{
                    card.style.display = '';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path


# ==============================================================================
# Main Orchestrator
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Extract latest bug bounty programs and evaluate for IDOR hunting.")
    parser.add_argument("--count", type=int, default=int(os.getenv("DEFAULT_COUNT", 2)), help="Number of programs per type per platform (default: 2)")
    parser.add_argument("--format", type=str, choices=["markdown", "html", "both", "md", "all"], default=os.getenv("DEFAULT_FORMAT", "both"), help="Report output format: markdown, html, or both (default: both)")
    parser.add_argument("--output", type=str, default="idor_targets_report", help="Output file base name (without extension, e.g. 'idor_targets_report')")
    parser.add_argument("--api-key", type=str, default=None, help="LLM API Key (or set LLM_API_KEY in .env)")
    parser.add_argument("--base-url", type=str, default=None, help="LLM Base URL (or set LLM_BASE_URL in .env)")
    parser.add_argument("--model", type=str, default=None, help="LLM Model name (or set LLM_MODEL in .env)")
    parser.add_argument("--no-auth", action="store_true", help="Force public discovery mode; ignores account credentials")
    parser.add_argument("--h1-user", type=str, default=None, help="HackerOne API username (or H1_API_IDENTIFIER in .env)")
    parser.add_argument("--h1-token", type=str, default=None, help="HackerOne API token (or H1_API_TOKEN in .env)")
    parser.add_argument("--ywh-token", type=str, default=None, help="YesWeHack Bearer JWT token (or YWH_API_TOKEN in .env)")
    parser.add_argument("--bc-session", type=str, default=None, help="Bugcrowd session cookie (or BUGCROWD_SESSION_TOKEN in .env)")

    args = parser.parse_args()

    # Normalize format argument
    fmt = args.format.lower()
    if fmt == "md":
        fmt = "markdown"
    elif fmt == "all":
        fmt = "both"

    api_key, base_url, model, auth_creds = load_config(args)
    if not api_key:
        print("[!] Error: No API key found. Please provide --api-key or configure LLM_API_KEY in .env.")
        sys.exit(1)

    has_auth = any(bool(v) for v in auth_creds.values()) and not args.no_auth

    print("==================================================================")
    print(" 🎯 BountyTargetScout - Target Extraction & IDOR Screening Bot")
    print(f" LLM Model: {model} | Base URL: {base_url}")
    print(f" Operating Mode: {'🔒 AUTHENTICATED (Private + Public)' if has_auth else '🌐 PUBLIC DISCOVERY ONLY'}")
    print(f" Rate Limiting: STRICT (Anti-Ban Safe, Circuit Breaker Active)")
    print(f" Report Format: {fmt.upper()} | Targets per Type: {args.count}")
    print("==================================================================\n")

    client = OpenAI(api_key=api_key, base_url=base_url)

    # 1. Fetch raw programs
    all_programs = []

    # Bugcrowd
    bc_vdp, bc_bounty = fetch_bugcrowd_programs(count_per_type=args.count, auth_creds=auth_creds)
    all_programs.extend(bc_vdp + bc_bounty)

    # YesWeHack
    ywh_vdp, ywh_bounty = fetch_yeswehack_programs(count_per_type=args.count, auth_creds=auth_creds)
    all_programs.extend(ywh_vdp + ywh_bounty)

    # HackerOne
    h1_vdp, h1_bounty = fetch_hackerone_programs(count_per_type=args.count, auth_creds=auth_creds)
    all_programs.extend(h1_vdp + h1_bounty)

    print(f"\n[*] Total targets extracted: {len(all_programs)}")

    # 2. Sort all programs chronologically by recency (newest launch/update first, private invites prioritized)
    all_programs.sort(
        key=lambda p: (
            p.get("visibility") == "Private",  # Prioritize private invites
            max(
                parse_timestamp_for_sort(p.get("last_updated_at")),
                parse_timestamp_for_sort(p.get("launched_at")),
            )
        ),
        reverse=True,
    )

    print("[*] Programs ranked chronologically (Private programs prioritized).")
    print("[*] Beginning parallel LLM evaluation of 7 IDOR criteria...\n")

    # 3. Evaluate with LLM in parallel
    evaluated_results = [None] * len(all_programs)

    def worker(item):
        idx, prog = item
        vis_tag = f"[{prog.get('visibility', 'Public')}]"
        print(f"[*] [{idx}/{len(all_programs)}] Evaluating [{prog['platform']}] {prog['name']} ({prog['type']} {vis_tag})...")
        eval_text = evaluate_program_with_llm(client, model, prog)
        score = calculate_score(eval_text)
        print(f"[+] [{idx}/{len(all_programs)}] Done [{prog['platform']}] {prog['name']} -> Score: {score}/7 (Launched: {prog.get('launched_at')})")
        return idx - 1, {"prog": prog, "eval": eval_text, "score": score}

    with ThreadPoolExecutor(max_workers=4) as executor:
        for pos, res in executor.map(worker, enumerate(all_programs, 1)):
            evaluated_results[pos] = res

    # 4. Generate Reports
    base_name = args.output
    if base_name.endswith(".md") or base_name.endswith(".html"):
        base_name = os.path.splitext(base_name)[0]

    generated_files = []

    if fmt in ["markdown", "both"]:
        md_file = os.path.abspath(f"{base_name}.md")
        generate_markdown_report(evaluated_results, md_file, model)
        generated_files.append(md_file)
        print(f"\n[+] Markdown Report generated: {md_file}")

    if fmt in ["html", "both"]:
        html_file = os.path.abspath(f"{base_name}.html")
        generate_html_report(evaluated_results, html_file, model)
        generated_files.append(html_file)
        print(f"[+] HTML Report generated:     {html_file}")

    print("\n==================================================================")
    print(" ✅ Execution Complete!")
    for f in generated_files:
        print(f"    -> {f}")
    print("==================================================================")


if __name__ == "__main__":
    main()
