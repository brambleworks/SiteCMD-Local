use super::router_coverage::{inspect, reports};

#[test]
fn a_router_with_quoted_preludes_and_an_ungated_chain_reports_auth() {
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
fn a_file_with_an_imported_limiter_and_a_subrouter_reports_rate_limits() {
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
fn a_router_importing_a_handler_with_a_final_redirect_reports_auth() {
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
fn an_ungated_router_mounted_under_admin_reports_sensitive_auth() {
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
