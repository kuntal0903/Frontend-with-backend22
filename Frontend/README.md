# ASM Shield 3.0 — Enterprise Attack Surface Intelligence

A futuristic, hyper-modern cybersecurity Attack Surface Management (ASM) web application built with React 19, Vite 6, Recharts, and Lucide Icons.

## 🚀 One-Click Deploy to Vercel

### Option 1: Via Vercel Dashboard (Recommended)
1. Go to [vercel.com/new](https://vercel.com/new).
2. Import the GitHub repository: **`kuntal0903/FRONTEND-3.0`**.
3. Select **Vite** as the Framework Preset (Vercel automatically detects `vercel.json` and Vite configuration).
4. Click **Deploy**.

### Option 2: Via Vercel CLI
```bash
npm i -g vercel
vercel
```

---

## 🛠 Local Development
```bash
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

## 📦 Production Build Verification
```bash
npm run build
```
The output will be generated in the `dist/` directory.

---

## ✨ Features & Architecture
- **Vercel Zero-Config Support**: Pre-configured `vercel.json` with SPA routing rewrite rules (`/(.*)` -> `/index.html`).
- **Live Recon & Radar Scanner**: Animated multi-threaded domain surface discovery with terminal console output.
- **Exposure Velocity & Severity Breakdown**: Multi-series area chart tracking Critical, High, and Medium threat vectors over 7D/30D/90D timeframes.
- **Jira Vulnerability Ticket Integration**: Direct Jira ticket creation modal and automated ticket tracking (`SEC-2024-XXXX`).
- **Interactive Topbar & Digital Clock**: Live ticking 12-hour AM/PM and 24-hour format clock, theme switcher (Dark, Light, Blue), and system health diagnostics.
- **Full Interactive Modals & Toast System**: Animated toast notification feedback system across all security actions.
