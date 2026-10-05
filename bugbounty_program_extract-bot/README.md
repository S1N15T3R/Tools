# 🎯 BountyTargetScout (Bug Bounty IDOR Target Extraction & Screening Bot)

**BountyTargetScout** is a CLI reconnaissance tool for bug bounty hunters and application security researchers. It automatically extracts newly launched and recently updated programs across **HackerOne**, **Bugcrowd**, and **YesWeHack**, ranks them chronologically by recency, and screens their policies and scopes against **7 core IDOR / broken authorization prerequisites** using an LLM.

---

## ⚡ Key Highlights

- **Multi-Platform Scraping:** Automatically monitors public VDP and Bounty programs from HackerOne, Bugcrowd, and YesWeHack.
- **Accurate Timestamp Extraction:**
  - **HackerOne:** Queries GraphQL endpoint in parallel for precise `launched_at`, `started_accepting_at`, and `last_updated_at`.
  - **Bugcrowd:** Leverages category feeds (`category=bug_bounty`, `category=vdp`) and queries engagement changelogs to get real launch and update timestamps.
  - **YesWeHack:** Parses live program directory and detail timestamps.
- **Chronological Ranking:** Automatically ranks all candidate targets from freshest to oldest using minute-level timestamp sorting.
- **7-Point IDOR Screening:** Evaluates each target against:
  1. **Login and user accounts:** Authenticated web applications, SaaS platforms, fintech, or marketplaces.
  2. **Free, open self-registration:** Ability to easily create $\ge 2$ test accounts without KYC, credit cards, or vetting.
  3. **Multi-user / multi-tenant features:** Teams, roles, invites, comments, billing, file sharing.
  4. **Business logic in scope:** Logic flaws, IDOR, and access control not in out-of-scope exclusions.
  5. **Mid-size or newly launched program:** Avoids legacy tech monopolies; highlights fresh scopes.
  6. **Healthy program stats:** Fast first response time and high resolution efficiency.
  7. **API or mobile app in scope:** REST/GraphQL APIs, Swagger endpoints, iOS/Android apps.
- **Zero Hallucination Flagging:** Leaves criteria blank `[ ]` with an explicit notice when the policy doesn't provide enough data, ensuring only confirmed items are checked `[x]`.
- **Multi-Format Output:** Generates GitHub-flavored Markdown (`.md`) and a modern dark-mode responsive HTML (`.html`) dashboard with live filter buttons.
- **Zero-Secret Architecture:** Complete `.env` support with zero credentials committed to git.

---

## 🛠️ Installation

```bash
# 1. Clone repository
git clone https://github.com/S1N15T3R/bugbounty_program_extract-bot.git
cd bugbounty_program_extract-bot

# 2. Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and fill in your LLM settings (compatible with local Omniroute, OpenAI, OpenRouter, etc.):

```bash
cp .env.example .env
```

### Example `.env` File
```env
# LLM Provider Configuration
LLM_API_KEY=your_api_key_here
LLM_BASE_URL=http://localhost:20128/v1
LLM_MODEL=MY-gemini-3.8-flash

# Default CLI behavior
DEFAULT_FORMAT=both
DEFAULT_COUNT=2
```

---

## 🚀 How to Use

Run the bot directly using the virtual environment:

```bash
# Run with defaults (extracts 2 VDPs and 2 Bounties per platform, outputs both MD and HTML)
python bounty_target_scout.py

# Generate only the interactive HTML report
python bounty_target_scout.py --format html

# Generate only the Markdown report
python bounty_target_scout.py --format md

# Extract top 3 programs per type per platform and customize output name
python bounty_target_scout.py --count 3 --output my_targets
```

*(Note: `idor_bot.py` is symlinked to `bounty_target_scout.py` for backward compatibility).*

### CLI Arguments

| Argument | Description | Default |
|---|---|:---:|
| `--count` | Number of programs to extract per type per platform | `2` |
| `--format` | Output report format (`markdown`, `html`, `both`) | `both` |
| `--output` | Output filename base (without extension) | `idor_targets_report` |
| `--api-key` | LLM API key override | Loaded from `.env` |
| `--base-url` | LLM API base URL override | Loaded from `.env` |
| `--model` | LLM model identifier override | Loaded from `.env` |

---

## 📊 Report Artifacts

### 1. Interactive HTML Dashboard (`idor_targets_report.html`)
- Dark-theme cybersecurity UI.
- Top metrics summary (Total programs, High viability count, Bounty vs. VDP breakdown).
- Dynamic client-side filter buttons (`All`, `HackerOne`, `Bugcrowd`, `YesWeHack`, `Bounties`, `VDP`).
- Sortable executive matrix table with color-coded viability score pills.
- Detailed target cards with styled checkmarks and collapsible `<details>` scope drawers.

### 2. GitHub / Obsidian Markdown (`idor_targets_report.md`)
- Clean markdown tables and cards ready to paste into Obsidian, GitHub issues, or team documentation.
- Collapsible YAML code blocks for in-scope assets.
- Top Recommended Hunting Order section highlighting the highest-scoring fresh programs.

---

## 🔒 Security & Privacy

- All sensitive keys are strictly loaded via `.env` or system environment variables.
- `.gitignore` is pre-configured to exclude `.env`, `.env.*`, virtual environments (`venv/`), cache files, and generated scan reports from version control.
