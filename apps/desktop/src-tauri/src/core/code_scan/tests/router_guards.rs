use super::*;

fn router_report(router: &str) -> CodeScanReport {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "src/index.ts",
        &format!("{router}\napp.post(\"/ping\", (c) => c.text(\"ok\"));"),
    );
    write_file(
        temp.path(),
        "src/pages/billing.ts",
        r#"
export async function startCheckout(c) {
  const session = await loadSession(c);
  if (session.kind === "signed_out") return c.redirect("/sign-in");
  return c.text("ok");
}
"#,
    );
    write_file(
        temp.path(),
        "src/pages/account.ts",
        "export const deleteAccount = (c) => c.text('deleted');",
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
    write_file(
        temp.path(),
        "src/middleware.ts",
        "export const passThrough = async (c, next) => next();",
    );
    audit_project(temp.path()).unwrap()
}

fn finding<'a>(report: &'a CodeScanReport, prefix: &str) -> Option<&'a CodeIssue> {
    report
        .issues
        .iter()
        .find(|issue| issue.id == format!("{prefix}:src/index.ts"))
}

#[test]
fn a_router_whose_sensitive_routes_delegate_to_gated_handlers_is_not_unauthenticated() {
    let report = router_report(
        r#"
import { startCheckout as checkout } from "./pages/billing";
app.post("/billing/checkout", checkout);
app.get("/billing", (c) => c.redirect("/account/billing"));
"#,
    );
    assert!(
        finding(&report, "sensitive-auth").is_none(),
        "{:?}",
        report.issues
    );
}

#[test]
fn unprotected_sensitive_registrations_keep_auth_findings() {
    for registration in [
        "app.post(\"/account/delete\", deleteAccount);",
        "app.post(\"/admin/purge\", async (c) => { await db.purge(); return c.text('ok'); });",
        "app.post(\"/billing/checkout\", externalCheckout);",
        "app.post(dynamicPath, deleteAccount);",
        "app.post(\"/billing\", (c) => { db.purge(); return c.redirect('/'); });",
    ] {
        let report = router_report(&format!(
            r#"import {{ startCheckout }} from "./pages/billing";
import {{ deleteAccount }} from "./pages/account";
import {{ externalCheckout }} from "billing-sdk";
app.post("/billing/checkout", startCheckout);
{registration}
"#
        ));
        assert!(
            finding(&report, "sensitive-auth").is_some(),
            "{registration}: {:?}",
            report.issues
        );
    }
}

#[test]
fn a_router_that_mounts_an_imported_rate_limiter_is_limited() {
    for mount in ["app.use(\"*\", limitApi);", "app.use(limitApi);"] {
        let report = router_report(&format!(
            r#"import {{ limitApi }} from "./limits";
{mount}
app.get("/auth/callback", (c) => c.text("ok"));
"#
        ));
        assert!(
            finding(&report, "public-endpoint-rate-limit").is_none(),
            "{:?}",
            report.issues
        );
    }
}

#[test]
fn unrelated_or_path_scoped_middleware_keeps_public_endpoint_findings() {
    for mount in [
        "app.use(\"/api/*\", limitApi);",
        "app.use(\"*\", passThrough);",
    ] {
        let report = router_report(&format!(
            r#"import {{ limitApi }} from "./limits";
import {{ passThrough }} from "./middleware";
{mount}
app.get("/auth/callback", (c) => c.text("ok"));
"#
        ));
        assert!(
            finding(&report, "public-endpoint-rate-limit").is_some(),
            "{mount}: {:?}",
            report.issues
        );
    }
}

#[test]
fn cloudflare_rate_limiting_binding_is_rate_limit_evidence() {
    assert!(has_any(
        "env.MY_RATE_LIMITER.limit({ key: pathname })",
        &RATE_LIMIT_PATTERNS
    ));
}

#[test]
fn worker_dispatch_and_static_assets_are_not_outbound_calls() {
    for assets in [
        "",
        "app.get('/static/*', (c) => c.env.ASSETS.fetch(c.req.raw));",
    ] {
        let report = router_report(&format!(
            r#"{assets}
export default {{ async fetch(request: Request, env: Env, ctx: ExecutionContext) {{
  return app.fetch(request, env, ctx);
}} }};
"#
        ));
        for prefix in ["external-call-timeout", "external-call-retry"] {
            assert!(
                finding(&report, prefix).is_none(),
                "{prefix}: {:?}",
                report.issues
            );
        }
    }
}

#[test]
fn remote_fetches_and_service_bindings_still_need_outbound_guards() {
    for call in [
        "fetch('https://api.example.com/x')",
        "env.BACKEND.fetch(request)",
        "env.RENAMED_ASSETS.fetch(request)",
    ] {
        let report = router_report(&format!(
            r#"export default {{ async fetch(request, env, ctx) {{
  const asset = await env.ASSETS.fetch(request);
  return {call};
}} }};
"#
        ));
        for prefix in ["external-call-timeout", "external-call-retry"] {
            assert!(
                finding(&report, prefix).is_some(),
                "{call}: {prefix}: {:?}",
                report.issues
            );
            assert_eq!(finding(&report, prefix).unwrap().line, Some(3));
        }
    }
}

#[test]
fn a_global_limiter_does_not_require_the_handler_to_authenticate() {
    let report = router_report(
        r#"import { limitApi } from "./limits";
app.use("*", limitApi);
app.post("/billing/checkout", (c) => c.text("ok"));"#,
    );
    assert!(finding(&report, "public-endpoint-rate-limit").is_none());
    assert!(finding(&report, "sensitive-auth").is_some());
}

#[test]
fn rate_limit_middleware_on_another_router_does_not_cover_the_endpoint() {
    let report = router_report(
        r#"import { limitApi } from "./limits";
router.use("*", limitApi);
app.get("/auth/callback", (c) => c.text("ok"));"#,
    );
    assert!(finding(&report, "public-endpoint-rate-limit").is_some());
}

#[test]
fn session_reads_without_refusal_do_not_authenticate_delegated_routes() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "src/index.ts",
        r#"import { startCheckout } from "./billing";
app.post("/billing/checkout", startCheckout);"#,
    );
    write_file(temp.path(), "src/billing.ts", "export async function startCheckout(c) { const session = await loadSession(c); return c.text('ok'); }");
    let report = audit_project(temp.path()).unwrap();
    assert!(finding(&report, "sensitive-auth").is_some());
}

#[test]
fn imported_handlers_can_refuse_with_an_http_status() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "src/index.ts",
        r#"import { startCheckout } from "./pages/billing";
app.post("/billing/checkout", startCheckout);"#,
    );
    write_file(temp.path(), "src/pages/billing/index.ts", "export async function startCheckout(c) { const session = await loadSession(c); if (!session) return c.text('no', 401); return c.text('ok'); }");
    let report = audit_project(temp.path()).unwrap();
    assert!(finding(&report, "sensitive-auth").is_none());
}

#[test]
fn unresolved_sensitive_routes_anchor_the_auth_finding() {
    let report = router_report(
        r#"import { startCheckout } from "./pages/billing";
import { deleteAccount } from "./pages/account";
app.post("/billing/checkout", startCheckout);
app.post("/account/delete", deleteAccount);"#,
    );
    let issue = finding(&report, "sensitive-auth").unwrap();
    assert_eq!(issue.line, Some(4));
    assert!(issue
        .source_excerpt
        .as_deref()
        .unwrap()
        .contains("/account/delete"));
}

#[test]
fn a_router_can_delegate_after_local_middleware_and_a_trailing_comma() {
    let report = router_report(
        r#"import { startCheckout } from "./pages/billing";
app.post(
  "/billing/checkout",
  bodyLimit({ maxSize: 1024, onError: (c) => c.text("Too long.", 413) }),
  startCheckout,
);"#,
    );
    assert!(finding(&report, "sensitive-auth").is_none());
}

#[test]
fn a_trailing_comma_does_not_protect_an_ungated_handler() {
    let report = router_report(
        r#"import { deleteAccount } from "./pages/account";
import { startCheckout } from "./pages/billing";
app.post("/billing/checkout", startCheckout);
app.post("/account/delete", deleteAccount,);"#,
    );
    assert!(finding(&report, "sensitive-auth").is_some());
}
