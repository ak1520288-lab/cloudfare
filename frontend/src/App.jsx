import { useCallback, useEffect, useState } from "react";
import { apiRequest } from "./api";
import "../../backend/src/app.css";

const modules = [
  {
    id: "proxy",
    name: "Reverse proxy",
    detail: "Express forwards requests that pass the protection checks to the origin server.",
    status: "Active",
    icon: "↗",
  },
  {
    id: "ip_block",
    name: "IP blocklist",
    detail: "Redis checks whether a client IP has an active temporary block.",
    status: "Active",
    icon: "⊘",
  },
  {
    id: "rate_limit",
    name: "Rate limiting",
    detail: "Redis allows up to 30 requests per IP in 60 seconds, then blocks for 5 minutes.",
    status: "Active",
    icon: "◷",
  },
  {
    id: "waf",
    name: "Basic WAF",
    detail: "Checks request URLs, query parameters, and parsed bodies for common attack patterns.",
    status: "Active",
    icon: "⬡",
  },
  {
    id: "audit_log",
    name: "Request logging",
    detail: "Proxy, blocked, authentication, and admin events are persisted in MongoDB.",
    status: "Active",
    icon: "≡",
  },
  {
    id: "bot_score",
    name: "Bot behavior scoring",
    detail: "Fingerprinting, behavioral signals, and an adaptive risk score are the next module to build.",
    status: "Roadmap",
    icon: "◎",
  },
  {
    id: "challenge",
    name: "Challenge and CAPTCHA",
    detail: "Human verification for suspicious clients is not wired into the current proxy.",
    status: "Roadmap",
    icon: "◇",
  },
  {
    id: "forecast",
    name: "Predictive alerts",
    detail: "Attack forecasting needs historical traffic data and a trained model before it can be enabled.",
    status: "Roadmap",
    icon: "⌁",
  },
];

const pipeline = [
  {
    id: "ip_block",
    title: "IP block check",
    detail: "Reject an IP that already has a Redis block.",
    state: "Active",
  },
  {
    id: "rate_limit",
    title: "Rate limit",
    detail: "Count requests in a 60-second Redis window; block above 30.",
    state: "Active",
  },
  {
    id: "waf",
    title: "Basic WAF",
    detail: "Inspect the URL, query, and parsed body for known patterns.",
    state: "Active",
  },
  {
    id: "audit_log",
    title: "Request log",
    detail: "Log requests that pass the current checks to the backend console.",
    state: "Active",
  },
  {
    id: "proxy",
    title: "Origin proxy",
    detail: "Forward allowed traffic to ORIGIN_SERVER (default port 4000).",
    state: "Active",
  },
];

function Brand() {
  return (
    <a className="brand" href="#overview" aria-label="AntiFlair overview">
      <span className="brand-mark">A</span>
      <span>
        Anti<span className="brand-accent">Flair</span>
      </span>
    </a>
  );
}

function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("");
  const [authMode, setAuthMode] = useState("login");
  const [signedIn, setSignedIn] = useState(false);
  const [authChecking, setAuthChecking] = useState(true);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [url, setUrl] = useState("");
  const [simulation, setSimulation] = useState(null);
  const [summary, setSummary] = useState(null);
  const [events, setEvents] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [dashboardError, setDashboardError] = useState("");
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [blockIP, setBlockIP] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [blockBusy, setBlockBusy] = useState(false);
  const [chatQuestion, setChatQuestion] = useState("");
  const [chatMessages, setChatMessages] = useState([]);
  const [chatBusy, setChatBusy] = useState(false);
  const [chatError, setChatError] = useState("");

  useEffect(() => {
    let active = true;
    apiRequest("/auth/session")
      .then((data) => {
        if (!active) return;
        setUsername(data.user.username);
        setRole(data.user.role);
        setCsrfToken(data.csrfToken);
        setSignedIn(true);
      })
      .catch((error) => {
        if (!active || error.status === 401) return;
        setLoginError(error.message);
      })
      .finally(() => {
        if (active) setAuthChecking(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const loadDashboard = useCallback(async () => {
    setDashboardLoading(true);
    try {
      const [nextSummary, nextEvents, nextBlocks] = await Promise.all([
        apiRequest("/dashboard/summary"),
        apiRequest("/dashboard/events?limit=30"),
        apiRequest("/dashboard/blocks"),
      ]);
      setSummary(nextSummary);
      setEvents(nextEvents.events);
      setBlocks(nextBlocks.blocks);
      setDashboardError("");
    } catch (error) {
      if (error.status === 401) {
        setSignedIn(false);
        setCsrfToken("");
        setLoginError("Your session expired. Sign in again.");
      } else {
        setDashboardError(error.message);
      }
    } finally {
      setDashboardLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!signedIn) return undefined;
    const initialLoad = window.setTimeout(loadDashboard, 0);
    const interval = window.setInterval(loadDashboard, 15000);
    return () => {
      window.clearTimeout(initialLoad);
      window.clearInterval(interval);
    };
  }, [signedIn, loadDashboard]);

  async function handleLogin(event) {
    event.preventDefault();

    setLoginBusy(true);
    setLoginError("");
    try {
      const data = await apiRequest("/auth/login", {
        method: "POST",
        body: { username, password },
      });
      setUsername(data.user.username);
      setRole(data.user.role);
      setCsrfToken(data.csrfToken);
      setPassword("");
      setSignedIn(true);
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleSignup(event) {
    event.preventDefault();

    setLoginBusy(true);
    setLoginError("");
    try {
      const data = await apiRequest("/auth/signup", {
        method: "POST",
        body: { username, password },
      });
      setUsername(data.user.username);
      setRole(data.user.role);
      setCsrfToken(data.csrfToken);
      setPassword("");
      setSignedIn(true);
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleChatSubmit(event) {
    event.preventDefault();
    const question = chatQuestion.trim();
    if (question.length < 2 || question.length > 1000 || chatBusy) return;

    setChatMessages((messages) => [...messages, { role: "user", content: question }]);
    setChatQuestion("");
    setChatError("");
    setChatBusy(true);
    try {
      const data = await apiRequest("/dashboard/chat", {
        method: "POST",
        csrfToken,
        body: {
          question,
          history: chatMessages.slice(-8).map(({ role, content }) => ({ role, content })),
        },
      });
      setChatMessages((messages) => [...messages, { role: "assistant", content: data.answer }]);
    } catch (error) {
      setChatError(error.message);
    } finally {
      setChatBusy(false);
    }
  }

  async function handleLogout() {
    try {
      await apiRequest("/auth/session", {
        method: "DELETE",
        csrfToken,
      });
    } catch (error) {
      if (error.status !== 401) setLoginError(error.message);
    } finally {
      setSignedIn(false);
      setRole("");
      setCsrfToken("");
      setSummary(null);
      setEvents([]);
      setBlocks([]);
      setChatMessages([]);
    }
  }

  async function handleSimulation(event) {
    event.preventDefault();
    let target = url.trim();

    if (!target) {
      setSimulation({ type: "error", message: "Enter a domain to continue." });
      return;
    }

    if (!/^https?:\/\//i.test(target)) {
      target = `https://${target}`;
    }

    try {
      const parsed = new URL(target);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Unsupported protocol");
      }

      setUrl(target);
      const result = await apiRequest("/dashboard/inspect", {
        method: "POST",
        csrfToken,
        body: { url: parsed.href },
      });
      setSimulation({ type: "demo", ...result });
    } catch (error) {
      setSimulation({
        type: "error",
        message: error.message || "Enter a valid HTTP or HTTPS website address.",
      });
    }
  }

  async function handleBlockSubmit(event) {
    event.preventDefault();
    setBlockBusy(true);
    setDashboardError("");
    try {
      await apiRequest("/dashboard/blocks", {
        method: "POST",
        csrfToken,
        body: { ip: blockIP, reason: blockReason || undefined },
      });
      setBlockIP("");
      setBlockReason("");
      await loadDashboard();
    } catch (error) {
      setDashboardError(error.message);
    } finally {
      setBlockBusy(false);
    }
  }

  async function handleUnblock(ip) {
    try {
      await apiRequest(`/dashboard/blocks/${encodeURIComponent(ip)}`, {
        method: "DELETE",
        csrfToken,
      });
      await loadDashboard();
    } catch (error) {
      setDashboardError(error.message);
    }
  }

  if (authChecking) {
    return <main className="auth-loading" role="status">Checking your AntiFlair session…</main>;
  }

  if (!signedIn) {
    return (
      <main className="auth-screen">
        <section className="auth-story">
          <Brand />
          <div className="auth-story-copy">
            <span className="section-kicker">PBL PROJECT · EDGE SECURITY</span>
            <h1>
              A clearer way to
              <br />
              understand <span className="gradient-text">web protection.</span>
            </h1>
            <p>
              Explore a learning-focused reverse-proxy shield: see how traffic
              moves through IP filtering, Redis rate limits, WAF checks, and on
              to a protected origin.
            </p>
          </div>
          <div className="auth-capabilities">
            <span><i className="status-dot active-dot" /> Redis rate limiting</span>
            <span><i className="status-dot active-dot" /> Basic request filtering</span>
            <span><i className="status-dot roadmap-dot" /> AI and bot signals: roadmap</span>
          </div>
          <span className="auth-footnote">A student-built security project — not a Cloudflare replacement.</span>
        </section>

        <section className="auth-panel" aria-labelledby="login-title">
          <div className="auth-panel-inner">
            <div className="auth-symbol">⬡</div>
            <span className="section-kicker">{authMode === "login" ? "ANTI-FLAIR WORKSPACE" : "VIEWER ACCOUNT"}</span>
            <h2 id="login-title">{authMode === "login" ? "Welcome back" : "Create an account"}</h2>
            <p className="auth-description">
              {authMode === "login"
                ? "Sign in to explore the AntiFlair project dashboard."
                : "Create a read-only account to view the AntiFlair security dashboard."}
            </p>

            <form className="auth-form" onSubmit={authMode === "login" ? handleLogin : handleSignup}>
              <label htmlFor="username">USERNAME</label>
              <input
                autoComplete="username"
                id="username"
                name="username"
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Enter a demo username"
                required
                value={username}
              />

              <label htmlFor="password">PASSWORD</label>
              <input
                autoComplete={authMode === "login" ? "current-password" : "new-password"}
                id="password"
                name="password"
                onChange={(event) => setPassword(event.target.value)}
                placeholder={authMode === "login" ? "Your account password" : "At least 12 characters"}
                minLength={authMode === "signup" ? 12 : undefined}
                required
                type="password"
                value={password}
              />

              {loginError && (
                <p className="auth-error" role="alert">{loginError}</p>
              )}

              <button className="button-primary auth-submit" type="submit" disabled={loginBusy}>
                {loginBusy
                  ? authMode === "login" ? "Signing in…" : "Creating account…"
                  : authMode === "login" ? "Sign in" : "Create viewer account"} <span>→</span>
              </button>
            </form>

            <div className="auth-demo-note">
              <strong>{authMode === "login" ? "Backend-authenticated session" : "Viewer access only"}</strong>
              <span>
                {authMode === "login"
                  ? "Use the configured admin account or a registered viewer account. Passwords are verified with scrypt."
                  : "New accounts can view dashboard data but cannot manage IP blocks or use admin-only tools. Passwords are stored as scrypt hashes."}
              </span>
            </div>
            <button
              className="logout-button"
              type="button"
              onClick={() => {
                setAuthMode(authMode === "login" ? "signup" : "login");
                setLoginError("");
              }}
            >
              {authMode === "login" ? "Need an account? Sign up" : "Already registered? Sign in"}
            </button>
          </div>
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell console-shell">
      <header className="console-navbar">
        <Brand />
        <nav className="console-nav" aria-label="Main navigation">
          <a href="#overview">Overview</a>
          <a href="#request-flow">Request flow</a>
          <a href="#modules">Modules</a>
          {role === "admin" && <a href="#security-assistant">Security assistant</a>}
          <a href="#pbl-guide">PBL guide</a>
        </nav>
        <div className="console-user">
          <span className="avatar">{username.slice(0, 2).toUpperCase()}</span>
          <span className="console-username">{username}</span>
          <span className="console-username">{role === "admin" ? "Admin" : "Viewer"}</span>
          <button className="logout-button" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </header>

      <main className="console-content">
        <section className="console-hero" id="overview">
          <div>
            <span className="section-kicker">ANTI-FLAIR · PROJECT CONSOLE</span>
            <h1>Protect the origin.<br /><span className="gradient-text">Understand every step.</span></h1>
            <p>
              A transparent project dashboard for the controls implemented in
              this repository and the intelligent modules planned next.
            </p>
            <div className="console-actions">
              <a className="button-primary" href="#request-flow">View request flow <span>↓</span></a>
              <a className="button-secondary" href="#modules">Explore modules <span>→</span></a>
            </div>
          </div>
          <aside className="readiness-card">
            <div className="readiness-heading">
              <span className="readiness-icon">⬡</span>
              <span className={`status-pill ${summary?.services?.redis === "connected" && summary?.services?.mongo === "connected" ? "" : "service-warning"}`}>
                <i className={`status-dot ${summary?.services?.redis === "connected" && summary?.services?.mongo === "connected" ? "active-dot" : "roadmap-dot"}`} />
                {summary ? (summary.services.redis === "connected" && summary.services.mongo === "connected" ? "SERVICES CONNECTED" : "SERVICE DEGRADED") : "CONNECTING"}
              </span>
            </div>
            <strong>Core protection foundation</strong>
            <p>Redis: {summary?.services?.redis || "checking"} · MongoDB: {summary?.services?.mongo || "checking"}</p>
            <div className="readiness-track"><span /></div>
            <small>{summary?.services?.origin ? `Origin: ${summary.services.origin}` : "Live metrics load from the protected backend."}</small>
          </aside>
        </section>

        <section className="stat-strip" aria-label="Implemented protection modules">
          <article><span>FORWARDED · 24H</span><strong>{summary?.metrics.forwarded24h ?? "—"}</strong><small>Requests passed through the proxy</small></article>
          <article><span>BLOCKED · 24H</span><strong>{summary?.metrics.blocked24h ?? "—"}</strong><small>WAF, rate limit, IP, and auth events</small></article>
          <article><span>REQUESTS · 1 MIN</span><strong>{summary?.metrics.requestsLastMinute ?? "—"}</strong><small>{dashboardLoading ? "Refreshing…" : "Auto-refreshes every 15 seconds"}</small></article>
          <article><span>ACTIVE IP BLOCKS</span><strong>{summary?.metrics.activeBlocks ?? "—"}</strong><small>Temporary Redis blocks</small></article>
        </section>
        {dashboardError && <div className="dashboard-error" role="alert">{dashboardError}</div>}

        <section className="content-section" id="request-flow">
          <div className="section-heading left-heading">
            <span className="section-kicker">HOW A REQUEST IS PROTECTED</span>
            <h2>One request, checked in order.</h2>
            <p>The first five stages map to the current backend middleware chain. Statuses update from backend service health.</p>
          </div>
          <div className="pipeline-grid">
            {pipeline.map((step, index) => {
              const status = summary?.modules.find((module) => module.id === step.id)?.status || "checking";
              return (
              <article className="pipeline-card" key={step.title}>
                <span className="pipeline-number">{String(index + 1).padStart(2, "0")}</span>
                <span className={`pipeline-state ${status === "unavailable" ? "module-unavailable" : ""}`}>
                  <i className={`status-dot ${status === "active" ? "active-dot" : "roadmap-dot"}`} /> {status}
                </span>
                <h3>{step.title}</h3>
                <p>{step.detail}</p>
                {index < pipeline.length - 1 && <span className="pipeline-arrow" aria-hidden="true">→</span>}
              </article>
              );
            })}
          </div>
          <div className="decision-callout">
            <span className="decision-icon">i</span>
            <p><strong>Current decision:</strong> the IP filter, rate limiter, and WAF can reject requests. Requests that pass are logged to the console and persisted in MongoDB before being forwarded. The AI score, CAPTCHA, and central policy engine are not implemented yet.</p>
          </div>
        </section>

        <section className="content-section modules-section" id="modules">
          <div className="section-heading left-heading">
            <span className="section-kicker">PROTECTION MODULES</span>
            <h2>Working foundation. Clear roadmap.</h2>
            <p>Module status is explicit so a project demo does not mistake planned features for live defenses.</p>
          </div>
          <div className="module-grid">
            {modules.map((module) => {
              const status = summary?.modules.find((item) => item.id === module.id)?.status || "checking";
              const statusLabel = status === "active" ? "Active" : status === "roadmap" ? "Roadmap" : status === "checking" ? "Checking" : "Unavailable";
              return (
              <article className="module-card" key={module.name}>
                <div className="module-card-top">
                  <span className="module-icon">{module.icon}</span>
                  <span className={`module-status ${status === "active" ? "module-active" : status === "roadmap" ? "module-roadmap" : "module-unavailable"}`}>
                    <i className={`status-dot ${status === "active" ? "active-dot" : "roadmap-dot"}`} />
                    {statusLabel}
                  </span>
                </div>
                <h3>{module.name}</h3>
                <p>{module.detail}</p>
              </article>
              );
            })}
          </div>
        </section>

        <section className="content-section simulation-section" id="simulation">
          <div className="simulation-copy">
            <span className="section-kicker">INTERACTIVE WALKTHROUGH</span>
            <h2>Trace a sample website through the flow.</h2>
            <p>The backend checks the supplied URL path against the configured basic WAF rules. It does not fetch or scan the target website.</p>
            <span className="privacy-note"><span>◇</span> Target is never contacted</span>
          </div>
          <div className="simulation-card">
            <form onSubmit={handleSimulation}>
              <label htmlFor="website-url">SAMPLE WEBSITE</label>
              <div className="input-row">
                <span className="input-prefix">↗</span>
                <input
                  id="website-url"
                  onChange={(event) => {
                    setUrl(event.target.value);
                    setSimulation(null);
                  }}
                  placeholder="example.com"
                  type="text"
                  value={url}
                />
                <button className="scan-button" type="submit">Preview flow →</button>
              </div>
            </form>
            {simulation && (
              <div className={`scan-result ${simulation.type === "error" ? "error-result" : ""}`} role="status">
                <strong>{simulation.type === "error" ? "Check the address" : simulation.result === "would_block" ? "WAF rule matched" : "No basic rule matched"}</strong>
                {simulation.host && <code>{simulation.host}</code>}
                <p>{simulation.message}</p>
              </div>
            )}
          </div>
        </section>

        <section className="content-section events-section" id="events">
          <div className="section-heading left-heading">
            <span className="section-kicker">EVENTS & VISIBILITY</span>
            <h2>Live security and admin events.</h2>
            <p>Events come from the backend audit collection and refresh automatically. The requester IP is visible to the signed-in admin.</p>
          </div>
          <div className="events-table">
            <div className="events-table-head"><span>TIME</span><span>EVENT</span><span>DETAIL</span><span>STATUS</span></div>
            {events.map((item) => (
              <div className="events-table-row" key={item.requestId || `${item.createdAt}-${item.reason}-${item.ip}`}>
                <span>{new Date(item.createdAt).toLocaleString()}</span>
                <strong>{item.category.replaceAll("_", " ")} · {item.method || "admin"}</strong>
                <span>{item.path || item.reason || "—"}{item.ip ? ` · ${item.ip}` : ""}</span>
                <span className={`event-status ${item.outcome === "blocked" ? "event-blocked" : ""}`}>{item.outcome}{item.statusCode ? ` · ${item.statusCode}` : ""}</span>
              </div>
            ))}
            {!events.length && <p className="empty-state">{dashboardLoading ? "Loading security events…" : "No security events recorded yet. Send a request through the proxy to populate this table."}</p>}
          </div>
          <div className="block-controls">
            <div>
              <h3>Temporary IP blocks</h3>
              <p>Manage Redis blocks. IPv4 and IPv6 addresses are supported.</p>
              {role === "admin" && <form className="block-form" onSubmit={handleBlockSubmit}>
                <label htmlFor="block-ip">IP ADDRESS</label>
                <input id="block-ip" required value={blockIP} onChange={(event) => setBlockIP(event.target.value)} placeholder="203.0.113.10" />
                <label htmlFor="block-reason">REASON (OPTIONAL)</label>
                <input id="block-reason" value={blockReason} onChange={(event) => setBlockReason(event.target.value)} placeholder="Manual admin block" maxLength={120} />
                <button className="button-primary" type="submit" disabled={blockBusy}>{blockBusy ? "Applying…" : "Block IP"}</button>
              </form>}
            </div>
            <div className="block-list">
              {blocks.map((block) => (
                <div className="block-row" key={block.ip}>
                  <div><strong>{block.ip}</strong><span>{block.reason} · {Math.ceil(block.ttlSeconds / 60)} min left</span></div>
                  {role === "admin" && <button className="logout-button" onClick={() => handleUnblock(block.ip)}>Unblock</button>}
                </div>
              ))}
              {!blocks.length && <p className="empty-state">No active temporary IP blocks.</p>}
            </div>
          </div>
        </section>

        {role === "admin" && <section className="content-section assistant-section" id="security-assistant">
          <div className="section-heading left-heading">
            <span className="section-kicker">OPENROUTER · SECURITY Q&A</span>
            <h2>Ask a security question.</h2>
            <p>Get educational, defensive guidance about web security and this project. Questions are sent to OpenRouter by the backend and are not saved in the audit log.</p>
          </div>
          <div className="assistant-card">
            <div className="assistant-messages" aria-live="polite" aria-label="Chat messages">
              {!chatMessages.length && (
                <div className="assistant-message assistant-reply">
                  <strong>AntiFlair Assistant</strong>
                  <p>Ask about rate limiting, WAF rules, IP blocks, sessions, or safe security practices.</p>
                </div>
              )}
              {chatMessages.map((message, index) => (
                <div
                  className={`assistant-message ${message.role === "user" ? "assistant-user" : "assistant-reply"}`}
                  key={`${message.role}-${index}`}
                >
                  <strong>{message.role === "user" ? "You" : "AntiFlair Assistant"}</strong>
                  <p>{message.content}</p>
                </div>
              ))}
              {chatBusy && <p className="assistant-pending" role="status">Thinking…</p>}
            </div>
            {chatError && <p className="assistant-error" role="alert">{chatError}</p>}
            <form className="assistant-form" onSubmit={handleChatSubmit}>
              <label htmlFor="security-question">YOUR QUESTION</label>
              <textarea
                id="security-question"
                maxLength={1000}
                onChange={(event) => setChatQuestion(event.target.value)}
                placeholder="How does the rate limiter block repeated requests?"
                required
                rows={3}
                value={chatQuestion}
              />
              <div className="assistant-form-footer">
                <span>{chatQuestion.length}/1000 · Up to 8 questions per minute</span>
                <button className="button-primary" type="submit" disabled={chatBusy || chatQuestion.trim().length < 2}>
                  {chatBusy ? "Sending…" : "Ask assistant →"}
                </button>
              </div>
            </form>
          </div>
        </section>}

        <section className="content-section pbl-section" id="pbl-guide">
          <div className="section-heading left-heading">
            <span className="section-kicker">PBL IMPLEMENTATION PLAN</span>
            <h2>Build and present it step by step.</h2>
            <p>Use this sequence to set up the demo, explain the architecture, and scope the next intelligent module.</p>
          </div>
          <div className="steps-grid pbl-grid">
            <article className="step-card"><span className="step-number">01</span><h3>Start Redis</h3><p>Run Redis locally or with Docker; the proxy uses it for counters and temporary IP blocks.</p></article>
            <article className="step-card"><span className="step-number">02</span><h3>Start the origin</h3><p>Run the test origin on port 4000, or configure ORIGIN_SERVER for your own permitted test site.</p></article>
            <article className="step-card"><span className="step-number">03</span><h3>Start the shield</h3><p>Configure backend/.env and start the Express proxy on port 8080.</p></article>
            <article className="step-card"><span className="step-number">04</span><h3>Test safely</h3><p>Send normal requests through the proxy, then verify rate-limit and WAF responses in a controlled local setup.</p></article>
            <article className="step-card"><span className="step-number">05</span><h3>Show the flow</h3><p>Explain the order: IP block check → rate limiter → WAF → console log → origin proxy.</p></article>
            <article className="step-card"><span className="step-number">06</span><h3>Build the standout module</h3><p>Add a measurable bot-risk scorer, test it against labeled traffic, and only then consider challenge or adaptive policies.</p></article>
          </div>
          <div className="decision-callout roadmap-callout">
            <span className="decision-icon">★</span>
            <p><strong>Best next module:</strong> an explainable bot-risk scorer that combines request rate, header consistency, and request-path signals. Start in observe-only mode, measure false positives, and never present a heuristic as a trained AI model.</p>
          </div>
        </section>
      </main>

      <footer className="console-footer">
        <Brand />
        <span>Student project · Authenticated backend · MongoDB audit log · Redis sessions</span>
        <button className="logout-button" onClick={handleLogout}>Sign out</button>
      </footer>
    </div>
  );
}

export default App;
