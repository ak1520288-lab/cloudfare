# AntiFlair dashboard

The React/Vite dashboard talks to the Express backend at `/api`. During local
development, Vite forwards these requests to `http://127.0.0.1:8080` by
default. Set `ANTIFLAIR_API_URL` before starting Vite to use a different
backend address (for example, when the default port is occupied).

## Run

```powershell
npm install
npm run dev
```

Sign in with the username and password configured in `backend/.env`. The
backend verifies the password, sets an HttpOnly session cookie, and returns a
CSRF token that the frontend sends on state-changing admin requests. The
dashboard refreshes service metrics, retained security events, and active IP
blocks every 15 seconds.

The authenticated Security assistant sends questions to OpenRouter through the
backend. Set `OPENROUTER_API_KEY` in `backend/.env` to enable it; the key is
never included in frontend code. Questions use the configured OpenRouter model
and are not stored in the dashboard audit log.

The URL inspection UI asks the backend to apply local WAF rules to a URL path.
The target site is not contacted. Run `npm run lint` and `npm run build` to
validate the frontend.
