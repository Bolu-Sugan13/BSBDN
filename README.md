# BSBDN — Blockchain-Based Synthetic Bio-Digital Network (Mini Project)

Flask + SQLite implementation of the tamper-evident healthcare digital-twin platform.

## Setup

```bash
pip install -r requirements.txt
python seed.py        # creates bsbdn.db + a default admin account
python app.py          # runs at http://localhost:5000
```

Default admin login: `admin@bsbdn.local` / `admin123`

## Modules implemented

| Module | Where |
|---|---|
| User & Auth | `/register`, `/login` — role-based (patient / doctor / admin) |
| Data Ingestion | `/add-record` — manual entry, with source flagged as manual/wearable/hospital |
| Blockchain | `blockchain.py` — SHA-256 block chaining on every vitals write |
| Digital Twin Dashboard | `/dashboard` — SVG body, organs colored green/yellow/red from vitals thresholds |
| Vitals Analytics | `/analytics` — Chart.js line charts (heart rate, BP, SpO2) |
| Prediction | Linear trend projection (least-squares) shown as dashed line, served by `/api/vitals/<id>` |
| Blockchain Timeline | `/blockchain` — full chain log, hash + previous hash per block |
| Admin | `/admin` — users, record/block counts, activity log, "Run integrity check" (recomputes every hash) |

## How the tamper-evidence works

Every vitals record is stored *and* written into a block: `hash = SHA256(index + timestamp + data + previous_hash)`.
The Admin integrity check (`/admin/verify`, run from the Blockchain page) recomputes each block's hash from its
stored fields and re-checks the `previous_hash` links. If a row in `health_records` or `blocks` is edited directly
in the database (bypassing the app), the recomputed hash won't match the stored one, and the check flags the
exact block where the chain breaks — this is the demo to show for the "tamper-evident" requirement.

## Notes for the writeup

- Organ status thresholds are a simplified rule-based mapping (see `database.organ_status_from_vitals`) —
  clinically illustrative, not diagnostic. Worth stating this assumption explicitly in your report.
- Wearable/hospital "import" is simulated via a source dropdown on manual entry, rather than a live device
  integration — reasonable scope for a mini project; mention this as a Phase 2 extension if asked.
- Prediction uses a simple least-squares linear trend over past readings — enough to demonstrate the module
  without a heavier ML dependency.
