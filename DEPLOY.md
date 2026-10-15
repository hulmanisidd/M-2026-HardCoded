# Deploy notes

- **Live URL:** TODO
- **Host:** TODO (Render / Railway / organizers)
- **Tracked branch:** `bugbounty`
- **Start command:** `uvicorn webapp.app:app --host 0.0.0.0 --port $PORT`
- **Python:** 3.11
- **Secrets:** none

## Redeploy
1. Merge changes into `main`, then sync `main` into `bugbounty`
   (only before the 12:00 AM freeze; never touch `bugbounty` after).
2. The host auto-deploys on push, or trigger a manual deploy from its dashboard.
3. Smoke-test: all 8 scenarios load, empty state works, no console errors.

## Security notes
- Static files are served only from `webapp/static/`.
- UI has no inline scripts or styles, so the CSP is
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'`.
- The UI never uses innerHTML with API data.