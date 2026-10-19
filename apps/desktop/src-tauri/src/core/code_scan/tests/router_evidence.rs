use super::router_coverage::{inspect, reports};
use super::*;

#[test]
fn imported_identity_evidence_does_not_clear_router_findings() {
    for module in [
        r#"export async function deleteAccount(c) { const { userId } = await c.req.parseBody(); await db.delete(users).where(eq(users.id, userId)); return c.redirect("/goodbye"); }"#,
        r#"export async function getAccount(c) { const session = await loadSession(c); if (!session) return c.redirect("/login"); return c.json(session); } export async function deleteAccount(c) { await db.purge(); return c.redirect("/goodbye"); }"#,
        r#"export { deleteAccount } from "./unsafe"; export async function getAccount(c) { const session = await loadSession(c); if (!session) return c.redirect("/login"); return c.json(session); }"#,
        r#"export async function deleteAccount(c) { const session = await getCheckoutSession(c); return c.redirect("/goodbye"); }"#,
        r#"export async function deleteAccount(c) { const session = await loadSession(c); const denied = [401, 403].includes(session.status); return c.redirect("/goodbye"); }"#,
    ] {
        let report = inspect(
            "src/index.ts",
            r#"import { startCheckout } from "./pages/billing";
import { deleteAccount } from "./pages/account";
app.post("/billing/checkout", startCheckout);
app.post("/account/delete", deleteAccount);"#,
            &[("src/pages/account.ts", module)],
        );
        assert!(
            reports(&report, "sensitive-auth", "src/index.ts"),
            "{module}: {:?}",
            report.issues
        );
    }
    let report = inspect("src/index.ts", "import { startCheckout } from './pages/billing'; import { deleteAccount } from './pages/account'; app.post('/billing', startCheckout); app.post('/account/delete', deleteAccount);", &[("src/pages/account.ts", r#"
async function signedIn(c) {
    const session = await loadSession(c);
    if (!session) return c.redirect(c.req.path ? `/sign-in?next=${c.req.path}` : "/login");
    return session;
}
async function remove(c) {
    const session = await signedIn(c);
    if (session instanceof Response) return session;
    await db.purge();
    return c.text("ok");
}
export const deleteAccount = (c) => remove(c);
"#)]);
    assert!(reports(&report, "sensitive-auth", "src/index.ts"));
}

#[test]
fn identity_refusals_must_follow_the_lookup_in_a_bounded_window() {
    let module = format!("export async function deleteAccount(c) {{ const session = await loadSession(c); {} return c.redirect('/login'); }}", "doWork();".repeat(60));
    let report = inspect("src/index.ts", "import { startCheckout } from './pages/billing'; import { deleteAccount } from './pages/account'; app.post('/billing', startCheckout); app.post('/account/delete', deleteAccount);", &[("src/pages/account.ts", &module)]);
    assert!(reports(&report, "sensitive-auth", "src/index.ts"));
}

#[test]
fn imported_logging_middleware_does_not_borrow_a_sibling_limiter() {
    for mount in ["app.use(\"*\", logger);", "app.use(logger);"] {
        let report = inspect(
            "src/index.ts",
            &format!(
                r#"import {{ logger, limitApi }} from "./middleware";
{mount}
app.use("/api/*", limitApi);
app.post("/auth/login", login);"#
            ),
            &[(
                "src/middleware.ts",
                r#"export const logger = async (c, next) => { console.log(c.req.path); await next(); };
export const limitApi = async (c, next) => { await c.env.API_RATE_LIMIT.limit({ key: 'k' }); await next(); };"#,
            )],
        );
        assert!(reports(
            &report,
            "public-endpoint-rate-limit",
            "src/index.ts"
        ));
    }
}

#[test]
fn reexported_limiters_are_not_proven_local_middleware() {
    let report = inspect("src/index.ts", "import { logger } from './middleware'; app.use('*', logger); app.post('/auth/login', login);", &[("src/middleware.ts", "export { logger } from './logger'; export const limitApi = async (c) => c.env.API_RATE_LIMIT.limit({ key: 'k' });")]);
    assert!(reports(
        &report,
        "public-endpoint-rate-limit",
        "src/index.ts"
    ));
}

#[test]
fn upstream_limit_errors_and_headers_are_not_caller_limits() {
    for marker in [
        "OpenAI.RateLimitError",
        "Anthropic.RateLimitError",
        "res.headers.get(\"X-RateLimit-Remaining\")",
        "RATE_LIMIT_EXCEEDED",
        "// TODO: Rate limit this",
    ] {
        assert!(!has_any(marker, &RATE_LIMIT_PATTERNS), "{marker}");
    }
}

#[test]
fn provider_rate_limit_errors_do_not_limit_ai_callers() {
    for handling in [
        "if (e instanceof OpenAI.RateLimitError) return new Response('busy', { status: 503 });",
        "res.headers.get('X-RateLimit-Remaining');",
        "const code = 'RATE_LIMIT_EXCEEDED';",
    ] {
        let temp = TempDir::new().unwrap();
        write_file(
            temp.path(),
            "src/routes/chat.ts",
            &format!(
                r#"import OpenAI from "openai";
export async function POST(req: Request) {{
 const {{ prompt }} = await req.json();
 try {{ return Response.json(await openai.chat.completions.create({{ model, messages: [{{ role: "user", content: prompt }}] }})); }}
 catch (e) {{ {handling} throw e; }}
}}"#
            ),
        );
        let report = audit_project(temp.path()).unwrap();
        assert!(
            reports(&report, "ai-rate-limit", "src/routes/chat.ts"),
            "{handling}"
        );
    }
}
