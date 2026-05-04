# SentinelView

Governance, risk, and compliance tooling for growing businesses: a **Streamlit** application for day-to-day workflows, plus a **Next.js** reference UI for a premium Security & Compliance Overview (portfolio and demos).

## Repository

**https://github.com/Marvosso/SentinelView**

## Main application (Streamlit)

Python dashboard for onboarding, evidence, policies, alerts, and client workspaces.

### Prerequisites

- Python 3.10+ recommended  
- `pip`

### Setup

```powershell
cd path\to\SentinelView
pip install -r requirements.txt
```

Optional extras (e.g. Supabase): see `requirements-optional.txt`.

### Run

```powershell
python -m streamlit run dashboard.py
```

Open the URL Streamlit prints (typically **http://localhost:8501**).

## Dashboard UI reference (Next.js)

Polished **Security & Compliance Overview** and shell navigation in `dashboard-ui-reference/` — same product story as the Streamlit “Security & Compliance” experience, suitable for screenshots, stakeholder demos, and LinkedIn.

### Prerequisites

- Node.js 20+ recommended  
- npm

### Setup & dev server

```powershell
cd dashboard-ui-reference
npm install
npm run dev
```

Open **http://localhost:3000** (redirects to `/security-overview`).

### Build

```powershell
npm run build
npm run lint
```

### Demo / mock data

- Append **`?demo=client`** (or **`?demo=full`**) to URLs for a filled **sample workspace** (overview KPIs, weekly insight, activity log, issues & fixes).
- Use the **Demo** toggle on Overview / Activity / Issues to switch without editing the URL.
- Mock copy and numbers live in `dashboard-ui-reference/lib/overview-demo-data.ts` and `dashboard-ui-reference/lib/mock-workspace.ts`.

## Project layout (high level)

| Path | Purpose |
|------|--------|
| `dashboard.py` | Streamlit entrypoint |
| `security_overview_ui.py`, `trust_center_ui.py` | Security & compliance overview UI |
| `dashboard-ui-reference/` | Next.js + Tailwind reference dashboard |
| `ingest_engine.py`, `event_db.py`, `client_*` | Data ingest, events, client workspace |
| `policy_*`, `onboarding_*` | Policies and onboarding |

## Contributing

Use a feature branch and open a pull request against `main`. Keep commits focused and messages clear.

Add a `LICENSE` file at the repo root when you pick a license.
