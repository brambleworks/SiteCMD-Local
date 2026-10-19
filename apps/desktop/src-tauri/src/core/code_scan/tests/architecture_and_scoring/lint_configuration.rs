use super::super::*;

#[test]
fn an_eslint_config_is_not_a_god_module() {
    let temp = TempDir::new().unwrap();
    let mut content = String::from(
        r#"
                import { getServerSession } from "next-auth";
                import { z } from "zod";
                import { PrismaClient } from "@prisma/client";
                import Stripe from "stripe";
                import { Resend } from "resend";

                const stripe = new Stripe(process.env.STRIPE_SECRET!, { apiVersion: "2024-06-20" });
                const resend = new Resend(process.env.RESEND_API_KEY!);
                const prisma = new PrismaClient();

                export async function processOrder(email: string, priceId: string) {
                  const session = await getServerSession();
                  const input = z.object({ email: z.string(), priceId: z.string() }).parse({ email, priceId });
                  await prisma.order.create({ data: { email: input.email } });
                  await stripe.checkout.sessions.create({ line_items: [{ price: input.priceId, quantity: 1 }] });
                  await resend.emails.send({ to: input.email, subject: "hi", html: "<p>ok</p>" });
                  return Boolean(session);
                }
            "#,
    );
    for _ in 0..920 {
        content.push_str("// filler to simulate a giant service module\n");
    }

    write_file(temp.path(), "src/lib/billing.ts", &content);
    for name in [
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.cts",
        ".eslintrc.js",
        ".eslintrc.cjs",
    ] {
        write_file(temp.path(), name, &content);
    }
    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id == "god-module:src/lib/billing.ts"));
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| (issue.id.starts_with("god-module:")
                || issue.id.starts_with("oversized-module:"))
                && issue.relative_path != "src/lib/billing.ts"),
        "{:?}",
        report.issues
    );
}

#[test]
fn oversized_eslint_configs_still_run_secret_and_sink_checks() {
    let temp = TempDir::new().unwrap();
    let content = format!("export const pem = `-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----`;\nawait prisma.item.findMany();\nconst bio = <div dangerouslySetInnerHTML={{{{ __html: user.bio }}}} />;\n{}", "A".repeat(64), "// filler\n".repeat(920)); // gitleaks:allow
    write_file(temp.path(), "nested/eslint.config.js", &content);
    write_file(temp.path(), "src/lib/billing.ts", &content);
    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id == "oversized-module:src/lib/billing.ts"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id == "hardcoded-secret:nested/eslint.config.js"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.id.starts_with("unsafe-html:nested/eslint.config.js:")));
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.id == "oversized-module:nested/eslint.config.js"));
}
