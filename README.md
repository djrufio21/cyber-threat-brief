# Cyber Threat Brief

Every hour, GitHub runs a Python script that collects what is happening in cybersecurity threats worldwide and publishes it as one page you can read on your phone.

## What's on the page

| Section | Source | Looks back |
|---|---|---|
| **Actively Exploited** | CISA Known Exploited Vulnerabilities catalog. Every entry is confirmed exploited in the wild. Links go to the NVD record. | 7 days |
| **Breaking Threats** | The Hacker News, BleepingComputer, SecurityWeek, The Record, Dark Reading, Krebs on Security | 24 hours |
| **APAC Watch** | Google News search for attacks, breaches and ransomware across 10 APAC countries | 24 hours |
| **Threat Research** | Unit 42, Cisco Talos, Microsoft Threat Intelligence, Google Threat Intelligence, ESET, Check Point Research | 7 days |
| **Government Advisories** | CISA, ACSC Australia, HKCERT | 3 days |

At the top: how many exploited CVEs were added this week, how many are linked to ransomware, and tag buttons to filter the page.

**Tags** are added automatically from each headline: Exploited, Zero-day, Ransomware, Nation-state, Breach, Supply chain, Telecom, AI, Phishing, APAC. Stories that several outlets covered appear once, with "also in" listing the others.

## How it works

```
GitHub Actions (every hour, at 23 past)
        │
        ▼
threats.py reads sources.yml ──► CISA KEV (JSON) + RSS feeds ──► window, dedupe, tag
        │
        ▼
docs/index.html (latest) · docs/YYYY-MM-DD.html (archive) · briefs/YYYY-MM-DD.md
        │
        ▼
committed to the repo ──► GitHub Pages serves docs/ as the website
```

| File | What it does |
|---|---|
| `sources.yml` | Sources, sections, time windows and tag rules. The file to edit day to day. |
| `threats.py` | Fetches, filters, deduplicates, tags and writes the brief. |
| `.github/workflows/threat-brief.yml` | The schedule. |
| `docs/` | The website. |
| `briefs/` | A Markdown copy of each day's brief, readable on github.com. |

## Changing it

Edit `sources.yml` on github.com (pencil icon) and commit.

1. **Add a source:** add a `name` and RSS `url` under any section.
2. **Track a topic:** add a Google News feed with your own search after `q=`, for example `q=%22Salt+Typhoon%22+when:1d`.
3. **Add or adjust a tag:** add a line under `tags:`. Patterns match whole words, case insensitive.
4. **Change the time window or length:** edit `hours_back` and `max_items`.

To refresh outside the schedule, open the **Actions** tab, pick **Cyber threat brief**, and click **Run workflow**.

## Good to know

1. **Some sources block automated readers on some runs.** They are skipped and listed at the bottom of the page. If every source fails, the run fails, the previous brief stays up, and GitHub emails you.
2. **CISA's "patch deadline" applies to US federal agencies.** It is a useful urgency signal, not a deadline for you.
3. **Content from feeds is treated as untrusted.** HTML is stripped and escaped, only `http(s)` links are kept, and CVE IDs are validated before they are turned into links.
4. **The page asks search engines not to index it**, but the repo and page are public, so anyone with the link can read them. Everything on it is public information.
