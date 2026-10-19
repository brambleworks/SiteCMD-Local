use super::router_coverage::{inspect, reports};
use super::*;

#[test]
fn quotes_before_chained_routes_do_not_hide_ungated_handlers() {
    let mut missing = Vec::new();
    for prelude in [
        r#"const escape = (value) => value.replace(/"/g, "&quot;");"#,
        "const message = <p>Don't panic</p>;",
    ] {
        let report = inspect(
            "src/index.tsx",
            &format!(
                r#"import {{ startCheckout }} from "./pages/billing";
{prelude}
app.post("/billing/checkout", startCheckout).post("/admin/purge", purge);"#
            ),
            &[],
        );
        if !reports(&report, "sensitive-auth", "src/index.tsx") {
            missing.push(prelude);
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn an_imported_limiter_does_not_cover_an_exported_subrouter() {
    let report = inspect(
        "src/index.ts",
        r#"import { limitApi } from "./limits";
app.use("*", limitApi);
app.post("/ping", ping);
const api = new Hono();
api.post("/items", async (c) => { await db.insert(items).values(await c.req.json()); return c.json({ ok: true }); });
export { api };"#,
        &[],
    );
    assert!(reports(
        &report,
        "public-endpoint-rate-limit",
        "src/index.ts"
    ));
}

#[test]
fn an_imported_session_read_and_final_redirect_do_not_prove_a_gate() {
    let report = inspect(
        "src/index.ts",
        r#"import { startCheckout } from "./pages/billing";
import { deleteAccount } from "./pages/account";
app.post("/billing/checkout", startCheckout);
app.post("/account/delete", deleteAccount);"#,
        &[(
            "src/pages/account.ts",
            r#"export async function deleteAccount(c) {
  const session = await loadSession(c);
  await db.delete(users).where(eq(users.id, c.req.param("id")));
  return c.redirect("/login");
}"#,
        )],
    );
    assert!(reports(&report, "sensitive-auth", "src/index.ts"));
}

#[test]
fn a_sensitive_mount_in_another_file_keeps_the_router_auth_finding() {
    let report = inspect(
        "src/routes/users.ts",
        r#"import { Router } from "express";
import { showBilling } from "../pages/billing";
import { deleteUser } from "../handlers/users";
const router = Router();
router.get("/:id/billing", showBilling);
router.delete("/:id", deleteUser);
export default router;"#,
        &[
            ("src/index.ts", "import usersRoutes from './routes/users'; app.use('/admin/users', usersRoutes);"),
            ("src/pages/billing.ts", "export async function showBilling(c) { const session = await loadSession(c); if (!session) return c.redirect('/login'); return c.text('ok'); }"),
            ("src/handlers/users.ts", "export async function deleteUser(req, res) { await purgeUser(req.params.id); res.sendStatus(204); }"),
        ],
    );
    assert!(reports(&report, "sensitive-auth", "src/routes/users.ts"));
}

#[test]
fn mts_and_cts_files_are_outside_source_analysis() {
    let temp = TempDir::new().unwrap();
    let source = format!(
        "export const pem = `-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----`;", // gitleaks:allow
        "A".repeat(64)
    );
    let paths = [
        "src/keys.mts",
        "src/keys.cts",
        "src/keys.test.mts",
        "src/keys.test.cts",
        "types/index.d.mts",
        "types/index.d.cts",
    ];
    for path in paths {
        write_file(temp.path(), path, &source);
    }
    write_file(temp.path(), "src/keys.ts", &source);
    let report = audit_project(temp.path()).unwrap();
    assert!(reports(&report, "hardcoded-secret", "src/keys.ts"));
    let unexpected = paths
        .into_iter()
        .filter(|path| reports(&report, "hardcoded-secret", path))
        .collect::<Vec<_>>();
    assert!(unexpected.is_empty(), "{unexpected:?}");
}
