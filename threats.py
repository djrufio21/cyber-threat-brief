#!/usr/bin/env python3
"""Build a Cyber Threat Brief from CISA KEV plus security news, research and advisory feeds.

Reads sources.yml and writes:
  docs/index.html          the latest brief (the page GitHub Pages shows)
  docs/YYYY-MM-DD.html     a dated copy for the archive (the evening run replaces the morning one)
  docs/archive.html        list of past briefs
  briefs/YYYY-MM-DD.md     plain Markdown copy, readable on github.com
"""

import calendar
import datetime as dt
import difflib
import html
import json
import re
import socket
import sys
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

import feedparser
import yaml

ROOT = Path(__file__).resolve().parent
DOCS = ROOT / "docs"
BRIEFS = ROOT / "briefs"
MYT = ZoneInfo("Asia/Kuala_Lumpur")
USER_AGENT = "Mozilla/5.0 (compatible; CyberThreatBrief/1.0)"
SIMILARITY = 0.80  # titles this similar are treated as the same story

TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")

socket.setdefaulttimeout(25)


# ---------- helpers ----------

def clean_text(raw):
    """Strip HTML tags and entities so nothing from a feed can run on the page."""
    text = TAG_RE.sub(" ", raw or "")
    text = html.unescape(html.unescape(text))
    return SPACE_RE.sub(" ", text).strip()


def shorten(text, limit=240):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


def norm(title):
    return re.sub(r"[^a-z0-9 ]", "", title.lower())


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


STOPWORDS = set("the a an and or of for to in on at by with from new over after amid via its as is are was "
                "warns says said patches patched fixes fixed flaw flaws vulnerability vulnerabilities attack attacks".split())


def keywords(title):
    return {w for w in norm(title).split() if len(w) > 2 and w not in STOPWORDS}


def same_story(a, b):
    """Two headlines are the same story if they read alike or share most of their key words."""
    if difflib.SequenceMatcher(None, a["_key"], b["_key"]).ratio() >= SIMILARITY:
        return True
    shared = a["_words"] & b["_words"]
    smaller = min(len(a["_words"]), len(b["_words"])) or 1
    return len(shared) >= 4 and len(shared) / smaller >= 0.5


def compile_tags(config):
    # Whole words only (so "APAC" doesn't match "Apache"), allowing simple plurals.
    return {name: re.compile(r"\b(?:" + pattern + r")(?:s|es|ed)?\b", re.I)
            for name, pattern in (config.get("tags") or {}).items()}


def tag_story(story, tag_patterns):
    text = f"{story['title']} {story['summary']}"
    for name, pattern in tag_patterns.items():
        if name not in story["tags"] and pattern.search(text):
            story["tags"].append(name)


# ---------- sources ----------

def fetch_kev(feed, cutoff):
    """CISA Known Exploited Vulnerabilities: every entry is confirmed exploited in the wild."""
    request = urllib.request.Request(feed["url"], headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"[:120]

    stories = []
    for vuln in data.get("vulnerabilities", []):
        try:
            added = dt.datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
        except (KeyError, ValueError):
            continue
        if added < cutoff.replace(hour=0, minute=0, second=0, microsecond=0):
            continue
        cve = clean_text(vuln.get("cveID"))
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        ransomware = vuln.get("knownRansomwareCampaignUse", "").lower() == "known"
        due = vuln.get("dueDate", "")
        try:
            due = dt.date.fromisoformat(due).strftime("%-d %b")
        except ValueError:
            due = ""
        stories.append({
            "title": f"{cve}: {clean_text(vuln.get('vendorProject'))} {clean_text(vuln.get('product'))}",
            "subtitle": clean_text(vuln.get("vulnerabilityName")),
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "source": "CISA KEV",
            "published": added,
            "date_only": True,
            "summary": shorten(clean_text(vuln.get("shortDescription"))),
            "extra": (f"US federal patch deadline {due}" if due else ""),
            "tags": ["Exploited"] + (["Ransomware"] if ransomware else []),
            "also": [],
        })
    return stories, None


def fetch_rss(feed, cutoff):
    try:
        parsed = feedparser.parse(feed["url"], agent=USER_AGENT)
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"[:120]
    status = parsed.get("status", 200)
    if status >= 400:
        return [], f"HTTP {status}"
    if not parsed.entries:
        return [], str(parsed.get("bozo_exception") or "no items in feed")[:120]

    stories = []
    for entry in parsed.entries:
        stamp = entry.get("published_parsed") or entry.get("updated_parsed")
        if not stamp:
            continue
        published = dt.datetime.fromtimestamp(calendar.timegm(stamp), tz=dt.timezone.utc)
        if published < cutoff:
            continue
        title = clean_text(entry.get("title"))
        link = entry.get("link", "")
        if not title or not link.startswith(("http://", "https://")):
            continue

        source = feed["name"]
        if entry.get("source", {}).get("title"):  # Google News names the real outlet
            source = clean_text(entry.source.title)
            title = re.sub(r"\s+-\s+" + re.escape(source) + r"$", "", title)

        summary = clean_text(entry.get("summary"))
        if norm(summary).startswith(norm(title)[:40]):
            summary = ""
        stories.append({
            "title": title,
            "subtitle": "",
            "link": link,
            "source": source,
            "published": published,
            "date_only": False,
            "summary": shorten(summary),
            "extra": "",
            "tags": [],
            "also": [],
        })
    return stories, None


# ---------- assembly ----------

def build(config, now):
    tag_patterns = compile_tags(config)
    seen, sections, failures = [], [], []
    total_sources = 0

    for section in config["sections"]:
        cutoff = now - dt.timedelta(hours=section.get("hours_back", 24))
        is_kev = section.get("type") == "kev"
        candidates = []
        for feed in section["feeds"]:
            total_sources += 1
            stories, error = (fetch_kev if is_kev else fetch_rss)(feed, cutoff)
            if error:
                failures.append((section["name"], feed["name"], error))
                print(f"  ✗ {section['name']} / {feed['name']}: {error}", file=sys.stderr)
                continue
            print(f"  ✓ {section['name']} / {feed['name']}: {len(stories)} in window")
            candidates.extend(stories)

        candidates.sort(key=lambda s: s["published"], reverse=True)
        # A section with own_dedupe only merges duplicates within itself, so it is never emptied by others.
        pool = [] if section.get("own_dedupe") else seen
        kept = []
        for story in candidates:
            if not is_kev:  # KEV entries carry their own tags; free-text matching only adds noise there
                tag_story(story, tag_patterns)
                story["_key"], story["_words"] = norm(story["title"]), keywords(story["title"])
                match = next((o for o in pool if same_story(story, o)), None)
                if match:
                    if story["source"] != match["source"] and story["source"] not in match["also"]:
                        match["also"].append(story["source"])
                    for tag in story["tags"]:
                        if tag not in match["tags"]:
                            match["tags"].append(tag)
                    continue
                pool.append(story)
            if len(kept) < section.get("max_items", 15):
                kept.append(story)
        sections.append({"name": section["name"], "kev": is_kev, "stories": kept})

    return sections, failures, total_sources


def when(story, now):
    local = story["published"].astimezone(MYT)
    today = now.astimezone(MYT).date()
    if story["date_only"]:
        return "Added " + story["published"].strftime("%-d %b")
    if local.date() == today:
        return local.strftime("%-I:%M %p")
    if local.date() == today - dt.timedelta(days=1):
        return "Yesterday " + local.strftime("%-I:%M %p")
    return local.strftime("%-d %b")


def tag_counts(sections, tag_order):
    counts = {name: 0 for name in tag_order}
    for section in sections:
        for story in section["stories"]:
            for tag in story["tags"]:
                counts[tag] = counts.get(tag, 0) + 1
    return {k: v for k, v in counts.items() if v}


# ---------- rendering ----------

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#16191d;--muted:#5f6670;--line:#e2e5ea;--accent:#0a5bb5;--chip:#e9ecf1;
--red:#b42318;--redbg:#fde8e6;--amber:#9a5b00;--amberbg:#fff1d6;--violet:#5b3cc4;--violetbg:#ece8fb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e7e9ec;--muted:#98a0aa;--line:#262c34;
--accent:#79b2f2;--chip:#232831;--red:#ff8a80;--redbg:#3a1714;--amber:#f2c063;--amberbg:#33270f;--violet:#b8a6ff;--violetbg:#251e3d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:780px;margin:0 auto;padding:28px 16px 48px}
h1{margin:0;font-size:1.7rem;letter-spacing:-.01em}
.date{margin:2px 0 0;font-weight:600}
.meta{margin:4px 0 0;color:var(--muted);font-size:.9rem}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:16px 0 4px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 10px}
.stat b{display:block;font-size:1.35rem;line-height:1.2}
.stat span{color:var(--muted);font-size:.8rem}
.stat.hot b{color:var(--red)}
.filters{display:flex;flex-wrap:wrap;gap:6px;margin:16px 0 0}
.filters button{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:4px 11px;
font:inherit;font-size:.84rem;cursor:pointer}
.filters button[aria-pressed=true]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 0}
nav a{color:var(--accent);font-size:.88rem;text-decoration:none}
section{margin-top:28px}
h2{font-size:1rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--line);
padding-bottom:6px;margin:0 0 2px}
.note{color:var(--muted);font-size:.85rem;margin:4px 0 0}
ol{list-style:none;margin:0;padding:0}
li{padding:13px 0;border-bottom:1px solid var(--line)}
li[hidden]{display:none}
a.t{color:var(--ink);text-decoration:none;font-weight:600;font-size:1.01rem}
a.t:hover{color:var(--accent);text-decoration:underline}
.sub{margin:2px 0 0;font-weight:500;font-size:.93rem}
.s{margin:4px 0 0;color:var(--muted);font-size:.92rem}
.src{margin:6px 0 0;font-size:.8rem;color:var(--muted);display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center}
.src b{color:var(--accent);font-weight:600}
.tag{font-size:.72rem;font-weight:600;padding:1px 7px;border-radius:5px;background:var(--chip);color:var(--ink)}
.tag.Exploited,.tag.Zero-day{background:var(--redbg);color:var(--red)}
.tag.Ransomware{background:var(--amberbg);color:var(--amber)}
.tag.Nation-state,.tag.Telecom{background:var(--violetbg);color:var(--violet)}
.empty{color:var(--muted);padding:12px 0}
footer{margin-top:36px;color:var(--muted);font-size:.85rem}
footer a,.archive a{color:var(--accent)}
.archive li a{text-decoration:none;font-weight:600}
"""

FILTER_JS = """
<script>
(function(){
  var buttons=document.querySelectorAll('.filters button');
  buttons.forEach(function(btn){btn.addEventListener('click',function(){
    var tag=btn.getAttribute('data-tag');
    buttons.forEach(function(b){b.setAttribute('aria-pressed',b===btn?'true':'false')});
    document.querySelectorAll('li[data-tags]').forEach(function(li){
      li.hidden = tag!=='all' && (' '+li.getAttribute('data-tags')+' ').indexOf(' '+tag+' ')<0;
    });
  });});
})();
</script>
"""


def page(title, body, script=""):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body><main>
{body}
</main>{script}</body>
</html>
"""


def render_html(config, sections, failures, total_sources, now):
    e = html.escape
    local = now.astimezone(MYT)
    kev = next((s for s in sections if s["kev"]), None)
    kev_count = len(kev["stories"]) if kev else 0
    kev_ransom = sum("Ransomware" in s["tags"] for s in kev["stories"]) if kev else 0
    story_count = sum(len(s["stories"]) for s in sections if not s["kev"])
    counts = tag_counts(sections, list((config.get("tags") or {}).keys()))

    stats = [f"<div class='stat hot'><b>{kev_count}</b><span>exploited CVEs added (7 days)</span></div>",
             f"<div class='stat'><b>{kev_ransom}</b><span>linked to ransomware</span></div>",
             f"<div class='stat'><b>{story_count}</b><span>threat stories</span></div>"]

    filters = ["<button data-tag='all' aria-pressed='true'>All</button>"]
    filters += [f"<button data-tag='{slug(t)}' aria-pressed='false'>{e(t)} {n}</button>" for t, n in counts.items()]

    parts = [
        f"<header><h1>{e(config['settings']['title'])}</h1>",
        f"<p class='date'>{local.strftime('%A, %-d %B %Y')}</p>",
        f"<p class='meta'>Updated {local.strftime('%-I:%M %p')} MYT · {total_sources - len(failures)} of "
        f"{total_sources} sources responded</p></header>",
        "<div class='stats'>" + "".join(stats) + "</div>",
        "<div class='filters' role='group' aria-label='Filter by tag'>" + "".join(filters) + "</div>",
        "<nav>" + " · ".join(f"<a href='#{slug(s['name'])}'>{e(s['name'])}</a>" for s in sections) + "</nav>",
    ]

    for section in sections:
        parts.append(f"<section id='{slug(section['name'])}'><h2>{e(section['name'])}</h2>")
        if section["kev"]:
            parts.append("<p class='note'>Confirmed exploited in the wild by CISA. Patch these first.</p>")
        if not section["stories"]:
            parts.append("<p class='empty'>Nothing new in this window.</p></section>")
            continue
        parts.append("<ol>")
        for s in section["stories"]:
            tags = "".join(f"<span class='tag {e(t.replace(' ', '-'))}'>{e(t)}</span>" for t in s["tags"])
            sub = f"<p class='sub'>{e(s['subtitle'])}</p>" if s["subtitle"] else ""
            summary = f"<p class='s'>{e(s['summary'])}</p>" if s["summary"] else ""
            bits = [f"<b>{e(s['source'])}</b>", e(when(s, now))]
            if s["extra"]:
                bits.append(e(s["extra"]))
            if s["also"]:
                bits.append("also in " + e(", ".join(s["also"])))
            parts.append(
                f"<li data-tags='{' '.join(slug(t) for t in s['tags'])}'>"
                f"<a class='t' href='{e(s['link'])}' target='_blank' rel='noopener noreferrer'>{e(s['title'])}</a>"
                f"{sub}{summary}<p class='src'>{' · '.join(bits)} {tags}</p></li>"
            )
        parts.append("</ol></section>")

    parts.append("<footer><p><a href='archive.html'>Past briefs</a></p>")
    if failures:
        parts.append("<p>Skipped this run (source did not respond): "
                     + "; ".join(f"{e(sec)} / {e(name)}" for sec, name, _ in failures) + "</p>")
    parts.append("</footer>")
    return page(f"{config['settings']['title']} · {local.strftime('%-d %b %Y')}", "\n".join(parts), FILTER_JS)


def render_markdown(config, sections, failures, now):
    local = now.astimezone(MYT)
    lines = [f"# {config['settings']['title']}: {local.strftime('%A, %-d %B %Y')}",
             f"_Updated {local.strftime('%-I:%M %p')} MYT_", ""]
    for section in sections:
        lines += [f"## {section['name']}", ""]
        if not section["stories"]:
            lines += ["_Nothing new in this window._", ""]
            continue
        for s in section["stories"]:
            title = s["title"].replace("[", "(").replace("]", ")")
            tags = f" `{'` `'.join(s['tags'])}`" if s["tags"] else ""
            detail = ", ".join(x for x in [s["source"], when(s, now), s["extra"]] if x)
            lines.append(f"1. [{title}]({s['link']}) ({detail}){tags}")
        lines.append("")
    if failures:
        lines.append("Skipped this run: " + "; ".join(f"{sec} / {name}" for sec, name, _ in failures))
    return "\n".join(lines) + "\n"


def write_archive(config, keep_days, today):
    cutoff = today - dt.timedelta(days=keep_days)
    days = []
    for path in DOCS.glob("????-??-??.html"):
        day = dt.date.fromisoformat(path.stem)
        if day < cutoff:
            path.unlink()
        else:
            days.append(day)
    items = "".join(f"<li><a href='{d.isoformat()}.html'>{d.strftime('%A, %-d %B %Y')}</a></li>"
                    for d in sorted(days, reverse=True))
    body = (f"<header><h1>{html.escape(config['settings']['title'])}</h1>"
            f"<p class='meta'>Past briefs · <a href='index.html'>Latest</a></p></header>"
            f"<section class='archive'><ol>{items}</ol></section>")
    (DOCS / "archive.html").write_text(page("Past briefs", body), encoding="utf-8")


def main():
    config = yaml.safe_load((ROOT / "sources.yml").read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc)
    today = now.astimezone(MYT).date()
    print(f"Building threat brief for {today} (MYT)")

    sections, failures, total_sources = build(config, now)
    if len(failures) == total_sources:
        print("Every source failed. Not overwriting the site.", file=sys.stderr)
        return 1

    DOCS.mkdir(exist_ok=True)
    BRIEFS.mkdir(exist_ok=True)
    (DOCS / ".nojekyll").touch()
    page_html = render_html(config, sections, failures, total_sources, now)
    (DOCS / "index.html").write_text(page_html, encoding="utf-8")
    (DOCS / f"{today.isoformat()}.html").write_text(page_html, encoding="utf-8")
    (BRIEFS / f"{today.isoformat()}.md").write_text(render_markdown(config, sections, failures, now),
                                                     encoding="utf-8")
    write_archive(config, config["settings"].get("keep_days", 90), today)
    print(f"Done: {sum(len(s['stories']) for s in sections)} items, {len(failures)} source(s) skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
