use super::*;

pub(super) fn inspect(router_path: &str, router: &str, modules: &[(&str, &str)]) -> CodeScanReport {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), router_path, router);
    write_file(
        temp.path(),
        "src/pages/billing.ts",
        r#"
export async function startCheckout(c) {
  const session = await loadSession(c);
  if (!session) return c.redirect("/sign-in");
  return c.text("ok");
}
"#,
    );
    write_file(
        temp.path(),
        "src/limits.ts",
        r#"
export const limitApi = async (c, next) => {
  if (!(await c.env.SIGN_IN_RATE_LIMIT.limit({ key: "k" })).success) return c.text("", 429);
  await next();
};
"#,
    );
    for (path, content) in modules {
        write_file(temp.path(), path, content);
    }
    audit_project(temp.path()).unwrap()
}

pub(super) fn reports(report: &CodeScanReport, rule: &str, path: &str) -> bool {
    report
        .issues
        .iter()
        .any(|issue| issue.id == format!("{rule}:{path}"))
}

#[test]
fn sensitive_paths_outside_cleared_registrations_keep_auth_findings() {
    for extra in [
        r#"app.post("/billing/checkout", startCheckout).post("/admin/purge", async (c) => { await c.env.DB.prepare("DELETE FROM users").run(); return c.text("ok"); });"#,
        r#"app.post("/billing/checkout", startCheckout); const admin = new Hono(); admin.post("/purge", async (c) => { await c.env.DB.exec("DELETE FROM users"); return c.text("ok"); }); app.route("/admin", admin);"#,
        r#"app.post("/billing/checkout", startCheckout); export default { async fetch(request, env, ctx) { if (new URL(request.url).pathname === "/admin/purge") { await env.DB.exec("DELETE FROM users"); return new Response("ok"); } return app.fetch(request, env, ctx); } };"#,
        r#"app.get("/admin", (c) => c.redirect("/admin/dashboard")); const admin = new Hono(); admin.post("/purge", purge); app.route("/admin", admin); app.post("/ping", ping);"#,
        r#"app.post("/billing/checkout", startCheckout); app.on("POST", "/admin/purge", purge);"#,
        r#"app.post("/billing/checkout", startCheckout); app.use("/admin", adminRouter);"#,
        r#"app.post("/billing/checkout", startCheckout); api.post("/admin/purge", purge);"#,
        r#"app.post("/billing/checkout", startCheckout); app.route("/admin/purge").get(read).post(purge);"#,
        r#"app.post("/billing/checkout", startCheckout); instance.post("/admin/purge", purge);"#,
    ] {
        let report = inspect(
            "src/index.ts",
            &format!("import {{ startCheckout }} from './pages/billing';\n{extra}"),
            &[],
        );
        assert!(
            reports(&report, "sensitive-auth", "src/index.ts"),
            "{extra}: {:?}",
            report.issues
        );
    }
}

#[test]
fn public_routes_on_unobserved_routers_keep_rate_limit_findings() {
    let report = inspect(
        "src/index.ts",
        r#"import { limitApi } from "./limits";
app.use("*", limitApi);
app.post("/ping", ping);
api.post("/auth/login", login);"#,
        &[],
    );
    assert!(reports(
        &report,
        "public-endpoint-rate-limit",
        "src/index.ts"
    ));
}

#[test]
fn content_sensitive_path_words_keep_ungated_routes() {
    for path in [
        "/subscriptions/:id/cancel",
        "/payments/:id/refund",
        "/users/:id/role",
        "/users/:id/permission",
    ] {
        let report = inspect(
            "src/index.ts",
            &format!(
                r#"import {{ startCheckout }} from "./pages/billing";
app.post("/billing/checkout", startCheckout);
app.post("{path}", async (c) => {{ await stripe.subscriptions.cancel(c.req.param("id")); return c.json({{ ok: true }}); }});"#
            ),
            &[],
        );
        assert!(reports(&report, "sensitive-auth", "src/index.ts"), "{path}");
    }
}

#[test]
fn sensitive_router_paths_make_every_registration_sensitive() {
    let report = inspect("src/routes/admin.ts", r#"import { Router } from "express";
import { showSettings } from "../pages/settings";
const router = Router();
router.get("/settings", showSettings);
router.post("/users/:id/delete", async (req, res) => { await purgeUser(req.params.id); res.sendStatus(204); });
export default router;"#, &[("src/pages/settings.ts", "export async function showSettings(c) { const session = await loadSession(c); if (!session) return c.redirect('/login'); return c.text('ok'); }")]);
    assert!(reports(&report, "sensitive-auth", "src/routes/admin.ts"));
}

#[test]
fn global_limiters_mounted_after_routes_do_not_cover_them() {
    let report = inspect(
        "src/index.ts",
        r#"import { limitApi } from "./limits";
app.post("/auth/login", login);
app.use("*", limitApi);"#,
        &[],
    );
    assert!(reports(
        &report,
        "public-endpoint-rate-limit",
        "src/index.ts"
    ));
}

#[test]
fn computed_paths_on_unparsed_registrations_keep_auth_findings() {
    let mut missing = Vec::new();
    for registration in [
        "api.post(path, purge);",
        "export async function POST(req) { await db.purge(); return Response.json({ ok: true }); }",
        "export const POST = async (req) => { await db.purge(); return Response.json({ ok: true }); };",
        "export { purge as POST } from './unsafe';",
        "app.on('POST', path, purge);",
        "export default { async fetch(request, env, ctx) { if (request.method === 'POST') { await env.DB.exec('DELETE FROM users'); return new Response('ok'); } return app.fetch(request, env, ctx); } };",
    ] {
        let report = inspect("src/index.ts", &format!("import {{ startCheckout }} from './pages/billing'; app.post('/billing/checkout', startCheckout); {registration}"), &[]);
        if !reports(&report, "sensitive-auth", "src/index.ts") { missing.push(registration); }
    }
    assert!(missing.is_empty(), "{missing:?}");
}
