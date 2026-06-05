# Aegis OSINT AI Frontend

Next.js 16 App Router console for the Aegis passive OSINT backend.

## Run

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Configuration

The frontend can render without a running backend by using deterministic sample data. Set these variables to connect it to services:

```bash
NEXT_PUBLIC_AEGIS_API_URL=http://localhost:8000
NEXT_PUBLIC_AEGIS_WS_URL=ws://localhost:8000/api/v1/events
```

`NEXT_PUBLIC_AEGIS_API_URL` is used by server-rendered pages for investigations, targets, findings, and reports. `NEXT_PUBLIC_AEGIS_WS_URL` is used by the live timeline client component; without it, the timeline falls back to a local heartbeat stream.

## Checks

```bash
npm run lint
npm run build
```
