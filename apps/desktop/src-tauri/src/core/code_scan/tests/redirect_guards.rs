use super::*;

#[test]
fn accepts_a_validated_destination_with_a_safe_fallback() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "app/api/continue/route.mjs",
        r#"export function GET(request) {
  const url = new URL(request.url);
  const next = url.searchParams.get('next') || '/dashboard';
  let target = new URL('/dashboard', url.origin);
  if (next.startsWith('/') && !next.startsWith('//') && !next.includes('\\')) {
    const candidate = new URL(next, url.origin);
    if (candidate.origin === url.origin) target = candidate;
  }
  return Response.redirect(target, 302);
}"#,
    );

    let report = audit_project(temp.path()).unwrap();
    assert!(!report
        .issues
        .iter()
        .any(|issue| issue.check_id == "code_scan.open-redirect"));
}

#[test]
fn reports_open_redirect_when_request_origin_is_only_a_url_base() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "app/api/continue/route.mjs",
        r#"export function GET(request) {
  const url = new URL(request.url);
  const next = url.searchParams.get('next') || '/dashboard';
  return Response.redirect(new URL(next, url.origin), 302);
}"#,
    );

    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.check_id == "code_scan.open-redirect"));
}

#[test]
fn reports_open_redirect_when_only_a_slash_prefix_is_checked() {
    let temp = TempDir::new().unwrap();
    write_file(
        temp.path(),
        "app/api/continue/route.mjs",
        r#"export function GET(request) {
  const url = new URL(request.url);
  const next = url.searchParams.get('next') || '/dashboard';
  if (!next.startsWith('/')) return Response.redirect(new URL('/dashboard', url.origin), 302);
  return Response.redirect(new URL(next, url.origin), 302);
}"#,
    );

    let report = audit_project(temp.path()).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.check_id == "code_scan.open-redirect"));
}

#[test]
fn reports_destinations_not_protected_by_nearby_validation() {
    let cases = [
        ("origin read", "void url.origin; return Response.redirect(new URL(next, url.origin));"),
        ("hostname read", "void url.hostname; return Response.redirect(new URL(next, url.origin));"),
        ("host read", "void url.host; return Response.redirect(new URL(next, url.origin));"),
        ("unused helper", "normalizeReturnTo(next); return Response.redirect(new URL(next, url.origin));"),
        ("unused allowlist", "const allowedOrigins = ['https://app.example']; return Response.redirect(new URL(next, url.origin));"),
        ("comparison without a branch", "const target = new URL(next, url.origin); target.origin === url.origin; return Response.redirect(target);"),
        ("conditionally skipped rejection", "const target = new URL(next, url.origin); if (request.headers.has('validate')) if (target.origin !== url.origin) { throw new Error('invalid'); } return Response.redirect(target);"),
        ("different target", "const approved = new URL('/dashboard', url.origin); if (approved.origin !== url.origin) { throw new Error('invalid'); } return Response.redirect(new URL(next, url.origin));"),
        ("self comparison", "const target = new URL(next, url.origin); if (target.origin === target.origin) return Response.redirect(target); return Response.redirect('/dashboard');"),
        ("normalizer followed by tainted data", "return Response.redirect(normalizeReturnTo(next) + next.slice(0));"),
        ("mutated fallback", "function replaceDestination(target, input) { target.href = input; } let target = new URL('/dashboard', url.origin); replaceDestination(target, next); return Response.redirect(target);"),
        ("mutated expected origin", "function replaceOrigin(value, input) { value.href = input; } replaceOrigin(url, next); const target = new URL(next, url.origin); if (target.origin === url.origin) return Response.redirect(target); return Response.redirect('/dashboard');"),
        ("pathname after normalization", "const target = new URL(next, url.origin); if (target.origin !== url.origin) { throw new Error('invalid'); } return Response.redirect(target.pathname);"),
        ("validation inside an uncalled function", "const target = new URL(next, url.origin); function validate() { if (target.origin !== url.origin) { throw new Error('invalid'); } } return Response.redirect(target);"),
    ];
    let mut missed = Vec::new();
    for (name, body) in cases {
        let temp = TempDir::new().unwrap();
        write_file(
            temp.path(),
            "app/api/continue/route.mjs",
            &format!(
                "export function GET(request) {{\nconst url = new URL(request.url);\nconst next = url.searchParams.get('next');\n{body}\n}}"
            ),
        );
        let report = audit_project(temp.path()).unwrap();
        if !report
            .issues
            .iter()
            .any(|issue| issue.check_id == "code_scan.open-redirect")
        {
            missed.push(name);
        }
    }
    assert!(
        missed.is_empty(),
        "unguarded destinations were missed: {missed:?}"
    );
}

fn reports_open_redirect(relative_path: &str, source: &str) -> bool {
    let temp = TempDir::new().unwrap();
    write_file(temp.path(), relative_path, source);
    audit_project(temp.path())
        .unwrap()
        .issues
        .iter()
        .any(|issue| issue.check_id == "code_scan.open-redirect")
}

#[test]
fn ignores_a_scan_handler_beside_a_route_that_redirects_elsewhere() {
    let source = r#"import { Hono } from "hono";

const app = new Hono();

app.get("/results", async (c) => {
  const rawUrl = c.req.query("url")?.trim();
  if (!rawUrl) return c.redirect("/");
  return c.redirect(resultPath(normalizePublicScanUrl(rawUrl).toString()), 301);
});

app.get("/img/pattern-matching.jpg", (c) => {
  return c.redirect("/pattern-matching.jpg", 301);
});

app.post("/api/scan", async (c) => {
  const parsedBody = scanRequestSchema.safeParse(await c.req.json());
  if (!parsedBody.success) return c.json({ error: "Invalid JSON body" }, 400);
  const body = parsedBody.data;
  const rawUrl = body.url?.trim();
  if (!rawUrl) return c.json({ error: "Missing 'url' field" }, 400);
  return c.json(await scanSite(normalizePublicScanUrl(rawUrl)));
});

export default app;
"#;

    assert!(!reports_open_redirect(
        "apps/wasitvibed.com/src/index.ts",
        source
    ));
}

#[test]
fn ignores_request_fields_and_redirects_in_different_route_handlers() {
    let cases = [
        (
            "hono",
            "src/index.ts",
            r#"import { Hono } from "hono";
const app = new Hono();
app.get("/go/:slug", (c) => c.redirect(shortLinkTarget(c.req.param("slug"))));
app.post("/api/feed", async (c) => {
  const body = await c.req.json();
  return c.json(await loadFeed(body.nextCursor));
});
export default app;
"#,
        ),
        (
            "exported verbs",
            "app/api/feed/route.ts",
            r#"export async function GET(request: Request) {
  const slug = new URL(request.url).pathname.slice(4);
  return Response.redirect(shortLinkTarget(slug), 302);
}

export async function POST(request: Request) {
  const body = await request.json();
  return Response.json(await loadFeed(body.nextCursor));
}
"#,
        ),
    ];
    let reported = cases
        .iter()
        .filter(|(_, path, source)| reports_open_redirect(path, source))
        .map(|(name, _, _)| *name)
        .collect::<Vec<_>>();
    assert!(
        reported.is_empty(),
        "separate handlers were paired: {reported:?}"
    );
}

#[test]
fn ignores_constant_redirects_beside_a_request_field() {
    let source = r#"import { Hono } from "hono";
const app = new Hono();
const HOME = "/dashboard";
app.post("/api/signup", async (c) => {
  const body = await c.req.json();
  await saveReturnPreference(body.returnTo);
  if (!body.email) return c.redirect("/signup?error=missing-email");
  return c.redirect(`${HOME}?welcome=1`, 303);
});
export default app;
"#;

    assert!(!reports_open_redirect("src/index.ts", source));
}

#[test]
fn ignores_a_validation_result_flag_beside_a_computed_redirect() {
    let source = r#"import { Hono } from "hono";
const app = new Hono();
app.post("/api/signup", async (c) => {
  const parsedBody = signupSchema.safeParse(await c.req.json());
  if (!parsedBody.success) return c.json({ error: "Invalid JSON body" }, 400);
  const account = await createAccount(parsedBody.data);
  return c.redirect(account.dashboardPath, 303);
});
export default app;
"#;

    assert!(!reports_open_redirect("src/index.ts", source));
}

#[test]
fn reports_request_redirects_that_share_a_handler_or_leave_it() {
    let cases = [
        (
            "local variable",
            r#"app.get("/health", (c) => c.redirect("/status"));
app.post("/login", async (c) => {
  const body = await c.req.json();
  const destination = body.redirectTo;
  return c.redirect(destination);
});"#,
        ),
        (
            "request-derived template",
            r#"app.get("/health", (c) => c.redirect("/status"));
app.post("/login", async (c) => {
  const body = await c.req.json();
  return c.redirect(`${body.returnTo}`);
});"#,
        ),
        (
            "express accessor",
            r#"app.post("/logout", (req, res) => res.redirect("/"));
app.get("/callback", (req, res) => {
  res.redirect(req.query.next);
});"#,
        ),
        (
            "helper outside the handler",
            r#"function finish(c, target) {
  return c.redirect(target);
}
app.post("/login", async (c) => {
  const body = await c.req.json();
  return finish(c, body.returnTo);
});"#,
        ),
        (
            "success destination",
            r#"app.post("/checkout/done", async (c) => {
  const body = await c.req.json();
  return c.redirect(body.successUrl);
});"#,
        ),
    ];
    let mut missed = Vec::new();
    for (name, routes) in cases {
        let source = format!(
            "import {{ Hono }} from \"hono\";\nconst app = new Hono();\n{routes}\nexport default app;\n"
        );
        if !reports_open_redirect("src/index.ts", &source) {
            missed.push(name);
        }
    }
    assert!(
        missed.is_empty(),
        "request redirects were missed: {missed:?}"
    );
}
