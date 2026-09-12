# SIEM Copilot — Threat Hunting & Incident Investigation

A production-quality frontend for a college S5 mini project: **"Cyber Security SIEM Copilot for Threat Hunting and Incident Investigation."**

Built with React + TypeScript + Tailwind CSS — dark enterprise SOC aesthetic, full routing, working data layer, 9 screens.

---

## Quick Start

```bash
npm install
npm run dev        # http://localhost:5173
npx tsc --noEmit  # type-check only
npm run build      # production build
```

---

## Project Structure

```
src/
├── app/                    # AppShell, Sidebar, TopBar
├── components/ui/          # Shared primitives (SeverityBadge, DataTable, Timeline…)
├── features/
│   ├── dashboard/          # / — Security Overview
│   ├── alerts/             # /alerts + /alerts/:id
│   ├── incidents/          # /incidents + /incidents/:id
│   ├── threat-hunting/     # /threat-hunting
│   ├── copilot/            # /copilot
│   ├── logs/               # /logs
│   ├── analytics/          # /analytics
│   └── settings/           # /settings
├── services/
│   ├── index.ts            # ← THE SWAP POINT
│   ├── SiemService.ts      # TypeScript interface
│   └── mock/               # MockSiemService + mockData
├── types/index.ts           # Domain interfaces
├── hooks/useAsync.ts        # Data-fetch hook
└── lib/utils.ts             # Helpers (cn, formatters, colors)
```

---

## Technologies

| Concern | Technology |
|---|---|
| Framework | React 18 + TypeScript (strict) |
| Build | Vite 5 |
| Styling | Tailwind CSS v3 |
| Routing | React Router v6 |
| Charts | Recharts |
| Icons | Lucide React |
| Fonts | IBM Plex Sans + IBM Plex Mono |

---

## Mock Data

Lives in **`src/services/mock/mockData.ts`**. Five attack scenarios:
1. Brute Force → Account Compromise (main demo chain, 25 failed logins → C2 connection)
2. Port Scan Detection
3. Credential Spray (5 accounts, low-and-slow)
4. Distributed Brute Force (3 IPs, 1 target)
5. Off-hours Suspicious Login

---

## Backend Integration (The Swap Point)

Edit **only** `src/services/index.ts`:

```typescript
// Current (mock):
import { MockSiemService } from './mock/MockSiemService';
export const siemService: SiemService = new MockSiemService();

// Future FastAPI backend:
import { HttpSiemService } from './api/HttpSiemService';
export const siemService: SiemService = new HttpSiemService('https://your-api.com');
```

Implement `SiemService` interface from `src/services/SiemService.ts` in your `HttpSiemService`. No other files change.

### Endpoint Mapping

| Method | FastAPI Route |
|---|---|
| `getDashboardStats()` | `GET /api/dashboard/stats` |
| `getLogs(filter, page, size)` | `GET /api/logs` |
| `getAlerts(filter, page, size)` | `GET /api/alerts` |
| `getAlertById(id)` | `GET /api/alerts/{id}` |
| `getIncidents(page, size)` | `GET /api/incidents` |
| `getIncidentById(id)` | `GET /api/incidents/{id}` |
| `getDetectionRules()` | `GET /api/rules` |
| `toggleDetectionRule(id, enabled)` | `PATCH /api/rules/{id}` |
| `runThreatHunt(query)` | `POST /api/hunt` |
| `sendCopilotMessage(msg, incidentId)` | `POST /api/copilot/message` |
| `getAnalytics(days)` | `GET /api/analytics?days=` |

---

## Critical Demo Journey

**Dashboard → click alert → Alert Details → View Incident → Incident Investigation → Ask Copilot → Copilot response**

Every step has a working navigation link to the next.
