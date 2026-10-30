use super::{
    has_inline_secret_guard, has_wp_handler_registration, has_wp_logged_in_action,
    is_example_like_path, is_json_ld_serialization_sink, is_sensitive_handler,
    is_server_action_like, is_test_like_path, is_wp_gated_surface, is_write_handler,
    max_db_writes_per_handler, public_risk_match, route_like_evidence,
    wp_rest_routes_all_have_permission_callbacks, SourceFile,
};
use std::path::Path;

/// The two predicates below return the evidence phrase in production so
/// findings can name what matched; the tests only care whether it matched.
fn is_route_like(file: &SourceFile, lower: &str) -> bool {
    route_like_evidence(file, lower).is_some()
}

fn is_publicly_abusable_route(file: &SourceFile, lower: &str) -> bool {
    public_risk_match(file, lower).is_some()
}

fn source_file(relative_path: &str, content: &str) -> SourceFile {
    SourceFile {
        absolute_path: std::path::PathBuf::from(relative_path),
        relative_path: relative_path.to_string(),
        line_count: content.lines().count(),
        inline_rust_tests: false,
        content: content.to_string(),
    }
}

#[test]
fn api_support_modules_are_not_routes() {
    let support = source_file(
        "apps/site/src/lib/api/auth.ts",
        "export function authorize() { return true; }",
    );
    let route = source_file(
        "apps/site/src/pages/api/auth.ts",
        "export const POST = async () => new Response();",
    );

    assert!(!is_route_like(
        &support,
        &support.content.to_ascii_lowercase()
    ));
    assert!(is_route_like(&route, &route.content.to_ascii_lowercase()));
}

#[test]
fn instructional_catalog_guides_are_scanned_source() {
    assert!(!is_example_like_path(Path::new(
        "apps/catalog/content/guides/code/security.ts"
    )));
}

#[test]
fn recognizes_rust_test_files() {
    assert!(is_test_like_path(Path::new(
        "src/commands/desktop_tests.rs"
    )));
    assert!(is_test_like_path(Path::new(
        "src/scoring/calculator_scan_tests.rs"
    )));
    assert!(is_test_like_path(Path::new("src/parser/lexer_test.rs")));
    assert!(is_test_like_path(Path::new("src/core/code_scan/tests.rs")));
    assert!(is_test_like_path(Path::new("crates/core/benches/parse.rs")));
    // `/tests/` was already covered by the shared directory convention.
    assert!(is_test_like_path(Path::new("crates/core/tests/api.rs")));
    // First-party Rust source is still analysed - including names that merely
    // end in "test.rs"/"tests.rs" without the underscore convention.
    assert!(!is_test_like_path(Path::new("src/commands/scan.rs")));
    assert!(!is_test_like_path(Path::new("src/attest.rs")));
    assert!(!is_test_like_path(Path::new("src/protests.rs")));
}

#[test]
fn leading_directory_segments_are_recognized_as_test_locations() {
    // Callers pass project-relative paths as well as absolute walk paths, so a
    // root-level test directory must match without a separator in front of it.
    assert!(is_test_like_path(Path::new(
        "e2e/fixtures/accessibility.ts"
    )));
    assert!(is_test_like_path(Path::new("tests/api.spec.ts")));
    assert!(is_test_like_path(Path::new("test/helpers.ts")));
    assert!(is_test_like_path(Path::new("__tests__/render.ts")));
    assert!(is_test_like_path(Path::new("spec/models/user_spec.rb")));
    // The absolute form keeps matching, and unrelated leading names do not.
    assert!(is_test_like_path(Path::new("/repo/e2e/fixtures/a.ts")));
    assert!(!is_test_like_path(Path::new("e2etools/runner.ts")));
    assert!(!is_test_like_path(Path::new("testing-library-setup.ts")));
}

#[test]
fn quoted_route_markers_are_rule_definitions_not_routes() {
    let rule_source = source_file(
        "src/scanner/rules.ts",
        r#"const MARKERS = ["app.post(", "router.post(", "export async function post("];"#,
    );
    let lower = rule_source.content.to_lowercase();
    assert!(!is_route_like(&rule_source, &lower));
    assert!(!is_write_handler(&lower));

    // Live declarations are code, not data: still route-like.
    let express = source_file(
        "server/index.js",
        "app.post('/contact', handler);\napp.use(express.json());\n",
    );
    let lower = express.content.to_lowercase();
    assert!(is_route_like(&express, &lower));
    assert!(is_write_handler(&lower));

    // Laravel declarations survive too.
    let laravel = source_file("routes/api.php", "Route::post('/billing', 'Ctl@save');\n");
    let lower = laravel.content.to_lowercase();
    assert!(is_route_like(&laravel, &lower));
    assert!(is_write_handler(&lower));

    let fqcn = source_file(
        "modules/billing/routes.php",
        "<?php\nnamespace Modules\\Billing;\n\\Route::post('/pay', [PayController::class, 'store']);\n",
    );
    let lower = fqcn.content.to_lowercase();
    assert!(is_route_like(&fqcn, &lower));
    assert!(is_write_handler(&lower));

    // A scanner defining the "use server" directive marker is not a server
    // action; a file carrying the real directive is.
    assert!(!is_server_action_like(
        r#"let hit = lower.contains("\"use server\"") || lower.contains("'use server'");"#
    ));
    assert!(is_server_action_like(
        "\"use server\";\nexport async fn x() {}"
    ));
}

#[test]
fn recognizes_example_and_fixture_files() {
    assert!(is_example_like_path(Path::new(
        "src/lib/fix-guides/security.ts"
    )));
    assert!(is_example_like_path(Path::new("examples/cors.ts")));
    assert!(is_example_like_path(Path::new("playground/tsconfig.json")));
    assert!(is_example_like_path(Path::new(
        "src/__fixtures__/payload.ts"
    )));
    assert!(is_example_like_path(Path::new(
        "components/Button.stories.tsx"
    )));
    assert!(is_example_like_path(Path::new("config.example.ts")));
    // Real source is not example-like.
    assert!(!is_example_like_path(Path::new("src/api/contact.ts")));
    assert!(!is_example_like_path(Path::new("src/lib/auth.ts")));
}

#[test]
fn recognizes_ruby_test_files() {
    assert!(is_test_like_path(Path::new(
        "spec/vulnerabilities/sql_injection_spec.rb"
    )));
    assert!(is_test_like_path(Path::new("spec/models/user_spec.rb")));
    assert!(is_test_like_path(Path::new("test/models/user_test.rb")));
    // First-party Ruby source is still analysed.
    assert!(!is_test_like_path(Path::new("app/controllers/users.rb")));
    assert!(!is_test_like_path(Path::new("lib/parser.rb")));
}

#[test]
fn recognizes_e2e_and_cypress_test_files() {
    assert!(is_test_like_path(Path::new(
        "apps/api/v2/src/modules/webhooks/controllers/webhooks.controller.e2e-spec.ts"
    )));
    assert!(is_test_like_path(Path::new("tests/booking.e2e.ts")));
    assert!(is_test_like_path(Path::new(
        "src/platform/bookings/controllers/e2e/add-guests.helper.ts"
    )));
    assert!(is_test_like_path(Path::new("cypress/flows/login.cy.ts")));
    // Deno/Go-style underscore test convention.
    assert!(is_test_like_path(Path::new(
        "packages/fresh/src/middlewares/cors_test.ts"
    )));
    assert!(is_test_like_path(Path::new("src/util_test.tsx")));
    // First-party source is still analysed.
    assert!(!is_test_like_path(Path::new(
        "apps/api/v2/src/modules/webhooks/webhooks.controller.ts"
    )));
    assert!(!is_test_like_path(Path::new("src/latest_test_helpers.ts")));
}

#[test]
fn recognizes_node_module_test_files() {
    assert!(is_test_like_path(Path::new(
        "tools/scripts/repo-guardrail-rules-unit.test.mjs"
    )));
    assert!(is_test_like_path(Path::new("src/config.spec.cjs")));
    assert!(is_test_like_path(Path::new("src/parser_test.cjs")));
    assert!(!is_test_like_path(Path::new("src/runtime.mjs")));
}

#[test]
fn wp_hook_registrations_are_route_like() {
    assert!(has_wp_handler_registration(
        "add_action('wp_ajax_save_settings', 'my_save');"
    ));
    assert!(has_wp_handler_registration(
        "add_action(\"admin_post_export\", 'my_export');"
    ));
    assert!(has_wp_handler_registration(
        "register_rest_route('myplugin/v1', '/items', $args);"
    ));
    // Prose mentions without the quoted hook prefix do not count.
    assert!(!has_wp_handler_registration(
        "// wired up through wp_ajax_ hooks elsewhere"
    ));
    // A rule-definition source quoting the markers themselves is not a WP
    // surface (the extra delimiter/escape in front gives it away).
    assert!(!has_wp_handler_registration(
        r#"["'wp_ajax_", "\"wp_ajax_", "'admin_post_", "register_rest_route("]"#
    ));
    assert!(!has_wp_logged_in_action(
        r#"["'wp_ajax_", "\"wp_ajax_", "'admin_post_", "\"admin_post_"]"#
    ));
}

#[test]
fn gated_surface_requires_no_public_registrations() {
    // Priv-only ajax: behind the login wall.
    assert!(is_wp_gated_surface("add_action('wp_ajax_save', 'h');"));
    // A nopriv variant or an unguarded REST route makes the file public.
    assert!(!is_wp_gated_surface(
        "add_action('wp_ajax_save', 'h'); add_action('wp_ajax_nopriv_save', 'h');"
    ));
    assert!(!is_wp_gated_surface(
        "add_action('wp_ajax_save', 'h'); register_rest_route('p/v1', '/x', $a);"
    ));
    // A REST route whose registration carries a permission_callback keeps
    // the surface gated; '__return_true' declares it public.
    assert!(is_wp_gated_surface(
        "register_rest_route('p/v1', '/x', ['permission_callback' => [$this, 'check']]);"
    ));
    assert!(!is_wp_gated_surface(
        "register_rest_route('p/v1', '/x', ['permission_callback' => '__return_true']);"
    ));
    // No WP hooks at all: not a WP surface.
    assert!(!is_wp_gated_surface("router.post('/x', handler);"));
}

#[test]
fn rest_permission_callback_counting_is_per_registration() {
    // Every registration guarded -> access-control evidence.
    assert!(wp_rest_routes_all_have_permission_callbacks(
        "register_rest_route('p/v1', '/a', ['permission_callback' => [$this, 'check']]);\n\
         register_rest_route('p/v1', '/b', ['permission_callback' => 'my_guard']);"
    ));
    // Two registrations, one callback: at least one route is unguarded.
    assert!(!wp_rest_routes_all_have_permission_callbacks(
        "register_rest_route('p/v1', '/a', ['permission_callback' => [$this, 'check']]);\n\
         register_rest_route('p/v1', '/b', $args);"
    ));
    // No REST routes at all: nothing to claim.
    assert!(!wp_rest_routes_all_have_permission_callbacks(
        "add_action('wp_ajax_save', 'h');"
    ));
}

#[test]
fn nopriv_only_actions_are_not_logged_in_evidence() {
    // A logged-in action is auth evidence and a write handler.
    assert!(has_wp_logged_in_action(
        "add_action('wp_ajax_save_settings', 'my_save');"
    ));
    // Registering BOTH variants still carries the logged-in one.
    assert!(has_wp_logged_in_action(
        "add_action('wp_ajax_submit', 'h'); add_action('wp_ajax_nopriv_submit', 'h');"
    ));
    // nopriv-only handlers are public: no auth, no session for CSRF.
    assert!(!has_wp_logged_in_action(
        "add_action('wp_ajax_nopriv_track', 'my_track');"
    ));
    assert!(!has_wp_logged_in_action(
        "add_action(\"admin_post_nopriv_contact\", 'my_contact');"
    ));
}

#[test]
fn recognizes_custom_credential_and_session_auth() {
    // Hand-rolled auth the identity-library patterns miss (input is already
    // lowercased by the caller).
    assert!(has_inline_secret_guard(
        "if (!safecompare(secret, expected)) throw new error();"
    ));
    assert!(has_inline_secret_guard(
        "const ok = await bcrypt.compare(pw, hash);"
    ));
    assert!(has_inline_secret_guard(
        "const token = derivesessiontoken(expected);"
    ));
    // No credential handling -> not an auth guard.
    assert!(!has_inline_secret_guard("return json({ ok: true });"));
}

#[test]
fn es_module_keywords_do_not_make_a_route_publicly_abusable() {
    let text_route = source_file(
        "app/llms.txt/route.ts",
        "import { render } from \"@/lib/llms\";\nexport const dynamic = \"force-static\";\nexport function GET() { return new Response(render()); }\n",
    );
    assert!(!is_publicly_abusable_route(
        &text_route,
        &text_route.content.to_ascii_lowercase()
    ));

    let import_route = source_file(
        "app/api/import/route.ts",
        "export async function POST() { return new Response(); }",
    );
    assert!(is_publicly_abusable_route(
        &import_route,
        &import_route.content.to_ascii_lowercase()
    ));

    let export_handler = source_file("src/server.ts", "app.post(\"/reports/export\", handler);");
    assert!(is_publicly_abusable_route(
        &export_handler,
        &export_handler.content.to_ascii_lowercase()
    ));

    // Compound route names keep matching: the boundary classes admit hyphen and
    // underscore, which the ES keyword form never carries.
    let hyphenated = source_file("src/server.ts", "app.post(\"/api/data-import\", handler);");
    assert!(is_publicly_abusable_route(
        &hyphenated,
        &hyphenated.content.to_ascii_lowercase()
    ));
    let underscored = source_file(
        "src/jobs.ts",
        "app.post(\"/reports/bulk_export\", handler);",
    );
    assert!(is_publicly_abusable_route(
        &underscored,
        &underscored.content.to_ascii_lowercase()
    ));

    // A module that only re-exports is still not a route name.
    let re_export = source_file(
        "src/lib/index.ts",
        "export { renderLlmsIndex } from \"./llms\";\nexport type { Team } from \"./teams\";\n",
    );
    assert!(!is_publicly_abusable_route(
        &re_export,
        &re_export.content.to_ascii_lowercase()
    ));
}

#[test]
fn json_ld_serialization_is_not_a_raw_html_sink() {
    assert!(is_json_ld_serialization_sink(
        "React.createElement(\"script\", { type: \"application/ld+json\", dangerouslySetInnerHTML: { __html: JSON.stringify(data).replace(/</g, \"\\\\u003c\") } })"
    ));
    assert!(is_json_ld_serialization_sink(
        "<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: JSON.stringify(json) }} />"
    ));
    // A serialized value without the script type, or a second raw sink, stays dangerous.
    assert!(!is_json_ld_serialization_sink(
        "<div dangerouslySetInnerHTML={{ __html: JSON.stringify(json) }} />"
    ));
    // JSON.stringify does not escape `<`, so the same serialization outside the
    // JSON-LD script is still a markup sink: a JSON-LD block in the same file
    // must not excuse it, in either order.
    assert!(!is_json_ld_serialization_sink(
        "<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />\n<div dangerouslySetInnerHTML={{ __html: JSON.stringify(userProfile) }} />"
    ));
    assert!(!is_json_ld_serialization_sink(
        "<div dangerouslySetInnerHTML={{ __html: JSON.stringify(userProfile) }} />\n<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />"
    ));
    assert!(!is_json_ld_serialization_sink(
        "<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: JSON.stringify(json) }} /><div dangerouslySetInnerHTML={{ __html: html }} />"
    ));
    assert!(!is_json_ld_serialization_sink(
        "const t = \"application/ld+json\"; el.innerHTML = \"<b>\" + body + \"</b>\";"
    ));
}

#[test]
fn db_writes_are_counted_per_function_or_method_body_in_js_and_ts() {
    let one_each = source_file(
        "lib/actions/tips.ts",
        "export async function a() {\n  await db.from(\"tips\").insert({});\n}\n\nexport const b = async (id: string) => {\n  await db.from(\"tips\").update({}).eq(\"id\", id);\n};\n\nfunction c() {\n  return db.from(\"tips\").delete();\n}\n",
    );
    assert_eq!(max_db_writes_per_handler(&one_each, &one_each.content), 1);

    let two_in_one = source_file(
        "app/api/checkout/route.ts",
        "export async function POST() {\n  await prisma.order.create({});\n  await prisma.auditLog.create({});\n}\n\nexport async function DELETE() {\n  await prisma.order.delete({});\n}\n",
    );
    assert_eq!(
        max_db_writes_per_handler(&two_in_one, &two_in_one.content),
        2
    );

    // Brace balancing separates indented functions too, which the earlier
    // column-zero split could not do.
    let indented = source_file(
        "app/api/checkout/route.ts",
        "    export async function POST() {\n      await prisma.order.create({});\n    }\n    export async function PUT() {\n      await prisma.order.update({});\n    }\n",
    );
    assert_eq!(max_db_writes_per_handler(&indented, &indented.content), 1);

    // Class methods are bodies as well: a repository with one write per method
    // is not a multi-step write.
    let repository = source_file(
        "apps/api/src/modules/apps/apps.repository.ts",
        "export class AppsRepository {\n  async createApp(data: AppInput) {\n    return await this.prisma.app.create({ data });\n  }\n\n  async removeApp(id: string) {\n    return await this.prisma.app.delete({ where: { id } });\n  }\n}\n",
    );
    assert_eq!(
        max_db_writes_per_handler(&repository, &repository.content),
        1
    );

    // A write the handler never awaits is not part of a sequence a transaction
    // could wrap.
    let unawaited = source_file(
        "app/api/checkout/route.ts",
        "export async function POST() {\n  await prisma.order.create({});\n  void prisma.auditLog.create({});\n}\n",
    );
    assert_eq!(max_db_writes_per_handler(&unawaited, &unawaited.content), 1);

    // Two writes the handler never awaits still count as one: the file plainly
    // touches the database, and a zero would erase that classification for
    // every rule that reads this count.
    let none_awaited = source_file(
        "lib/actions/purge.ts",
        "export async function purge(id: string) {\n  const admin = createAdminClient();\n  admin.from(\"reports\").delete().eq(\"id\", id);\n  admin.from(\"audit\").delete().eq(\"id\", id);\n}\n",
    );
    assert_eq!(
        max_db_writes_per_handler(&none_awaited, &none_awaited.content),
        1
    );

    // Both writes inside one awaited Promise.all belong to the same statement.
    let concurrent = source_file(
        "app/api/checkout/route.ts",
        "export async function POST() {\n  await Promise.all([\n    prisma.order.create({ data: {} }),\n    prisma.auditLog.create({ data: {} }),\n  ]);\n}\n",
    );
    assert_eq!(
        max_db_writes_per_handler(&concurrent, &concurrent.content),
        2
    );

    // Top-level awaited writes sit in no function body at all. The busiest body
    // holds none of them, and the file must still read as touching a database.
    let module_scope = source_file(
        "scripts/seed.ts",
        "const log = (message: string) => {\n  console.log(message);\n};\n\nawait prisma.user.create({ data: {} });\nawait prisma.account.create({ data: {} });\n",
    );
    assert_eq!(
        max_db_writes_per_handler(&module_scope, &module_scope.content),
        1
    );

    // Other languages keep the whole-file count.
    let php = source_file(
        "app/Http/Controllers/OrderController.php",
        "<?php\nfunction store() {\n  DB::table('orders')->insert([]);\n}\nfunction destroy() {\n  DB::table('orders')->delete();\n}\n",
    );
    assert_eq!(max_db_writes_per_handler(&php, &php.content), 2);
}

#[test]
fn a_closed_json_ld_element_cannot_excuse_a_later_sink() {
    // Task 4 bound the exemption to the individual sink. The remaining gap was
    // a self-closing JSON-LD script followed by a sink expressed as an object
    // property with no intervening `<`: the look-back now stops at the closing
    // `>` as well as at an earlier sink.
    assert!(!is_json_ld_serialization_sink(
        "<script type=\"application/ld+json\" />\nconst props = { dangerouslySetInnerHTML: { __html: JSON.stringify(userProfile) } };\nreturn cloneElement(child, props);"
    ));
    // The documented shape still clears.
    assert!(is_json_ld_serialization_sink(
        "<script type=\"application/ld+json\" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />"
    ));
}

#[test]
fn route_paths_need_a_request_handler_in_javascript_but_not_in_other_languages() {
    let service = source_file(
        "apps/api/v2/src/modules/auth/auth.service.ts",
        "@Injectable()\nexport class AuthService {\n  getAuthMethods() {\n    return [];\n  }\n}\n",
    );
    assert!(!is_route_like(
        &service,
        &service.content.to_ascii_lowercase()
    ));

    let controller = source_file(
        "apps/api/v2/src/modules/auth/auth.controller.ts",
        "@Controller(\"auth\")\nexport class AuthController {\n  @Get(\"methods\")\n  methods() {\n    return [];\n  }\n}\n",
    );
    assert!(is_route_like(
        &controller,
        &controller.content.to_ascii_lowercase()
    ));

    // A handler reached through a factory is still a handler.
    let factory_handler = source_file(
        "packages/app-store/sendgrid/api/check.ts",
        "export async function getHandler(req: NextApiRequest) {\n  return {};\n}\n\nexport default defaultHandler({\n  GET: Promise.resolve({ default: defaultResponder(getHandler) }),\n});\n",
    );
    assert!(is_route_like(
        &factory_handler,
        &factory_handler.content.to_ascii_lowercase()
    ));

    let responder_handler = source_file(
        "packages/app-store/feishucalendar/api/add.ts",
        "async function getHandler(req: NextApiRequest) {\n  return { url };\n}\n\nexport default defaultResponder(getHandler);\n",
    );
    assert!(is_route_like(
        &responder_handler,
        &responder_handler.content.to_ascii_lowercase()
    ));

    // A default export of any other call is not a handler.
    let config_default = source_file(
        "packages/app-store/sendgrid/api/config.ts",
        "export default defineConfig({ name: \"sendgrid\" });\n",
    );
    assert!(!is_route_like(
        &config_default,
        &config_default.content.to_ascii_lowercase()
    ));

    // A component named for an HTTP verb, or for a Remix data export, is not a
    // handler: every framework that uses those names fixes their casing.
    let component = source_file(
        "app/routes/blog/post.tsx",
        "export function Post({ title }: { title: string }) {\n  return <article>{title}</article>;\n}\n",
    );
    assert!(!is_route_like(
        &component,
        &component.content.to_ascii_lowercase()
    ));
    let loader_component = source_file(
        "app/routes/blog/spinner.tsx",
        "export function Loader() {\n  return <div className=\"spinner\" />;\n}\n\nexport const Action = () => null;\n",
    );
    assert!(!is_route_like(
        &loader_component,
        &loader_component.content.to_ascii_lowercase()
    ));

    // A React Query module under a features `api/` directory is a client.
    let hook = source_file(
        "src/features/users/api/update-profile.ts",
        "export const updateProfile = (data: Profile) => api.patch(\"/users/profile\", data);\nexport const useUpdateProfile = () => useMutation({ mutationFn: updateProfile });\n",
    );
    assert!(!is_route_like(&hook, &hook.content.to_ascii_lowercase()));

    // A framework route that co-locates its loader with the page component is
    // still a route: the server marker outranks the client hooks beside it.
    let co_located = source_file(
        "app/routes/_unauthenticated+/organisation.invite.$token.tsx",
        "export async function loader({ params }: Route.LoaderArgs) {\n  return prisma.invite.findUnique({ where: { token: params.token } });\n}\n\nexport default function AcceptInvitationPage() {\n  const accept = trpc.invite.accept.useMutation();\n  return null;\n}\n",
    );
    assert!(is_route_like(
        &co_located,
        &co_located.content.to_ascii_lowercase()
    ));

    // An Express mount with a path argument is a route surface; a bare
    // middleware call is not.
    let mount = source_file(
        "apps/api/index.js",
        "const app = connect();\napp.use(\"/\", apiProxyV1);\n",
    );
    assert!(is_route_like(&mount, &mount.content.to_ascii_lowercase()));
    let middleware_only = source_file(
        "src/lib/server-helpers.ts",
        "export function attach(app) {\n  app.use(cors());\n}\n",
    );
    assert!(!is_route_like(
        &middleware_only,
        &middleware_only.content.to_ascii_lowercase()
    ));

    // Languages without a recognized handler convention keep the path rule.
    let rust_route = source_file(
        "src/routes/admin.rs",
        "async fn create_user(pool: PgPool) {\n    sqlx::query(\"SELECT 1\").execute(&pool).await;\n}\n",
    );
    assert!(is_route_like(
        &rust_route,
        &rust_route.content.to_ascii_lowercase()
    ));
}

#[test]
fn sensitive_path_words_match_whole_segments() {
    let transformer = source_file(
        "apps/api/v2/src/platform/transformers/api-to-internal/locations.ts",
        "export const POST = async () => new Response();",
    );
    assert!(!is_sensitive_handler(
        &transformer,
        &transformer.content.to_ascii_lowercase()
    ));

    let admin_page = source_file(
        "app/routes/_authenticated+/admin+/stats.tsx",
        "export async function loader() {\n  return {};\n}\n",
    );
    assert!(is_sensitive_handler(
        &admin_page,
        &admin_page.content.to_ascii_lowercase()
    ));

    let settings_route = source_file(
        "app/routes/_authenticated+/o.$orgUrl.settings.billing.tsx",
        "export async function loader() {\n  return {};\n}\n",
    );
    assert!(is_sensitive_handler(
        &settings_route,
        &settings_route.content.to_ascii_lowercase()
    ));
}

#[test]
fn orm_member_calls_do_not_satisfy_express_route_markers() {
    let script = source_file(
        "packages/prisma/delete-app.ts",
        "await prisma.app.delete({ where: { slug } });\nawait prisma.credential.deleteMany({ where: { appId } });\n",
    );
    assert!(!is_route_like(
        &script,
        &script.content.to_ascii_lowercase()
    ));

    let express = source_file("src/server.ts", "app.delete(\"/items/:id\", handler);\n");
    assert!(is_route_like(
        &express,
        &express.content.to_ascii_lowercase()
    ));

    // A named router is still a router: only the member dot marks a receiver
    // the marker does not own.
    let named_router = source_file(
        "src/routes/users.ts",
        "usersRouter.post(\"/users\", handler);\n",
    );
    let named_router_lower = named_router.content.to_ascii_lowercase();
    assert!(is_route_like(&named_router, &named_router_lower));
    assert!(is_write_handler(&named_router_lower));
}

#[test]
fn test_support_and_sample_trees_are_classified_as_such() {
    assert!(is_test_like_path(Path::new(
        "apps/react-vite/src/testing/test-utils.tsx"
    )));
    assert!(is_test_like_path(Path::new(
        "packages/users/UserRepository.integration-test.ts"
    )));
    assert!(is_test_like_path(Path::new("packages/users/user-test.ts")));
    assert!(is_example_like_path(Path::new(
        "sample/19-auth-jwt/src/users/users.service.ts"
    )));
    assert!(is_example_like_path(Path::new("samples/basic/src/main.ts")));
    // A shipped module whose name merely contains the word stays in scope.
    assert!(!is_test_like_path(Path::new("src/lib/latest.ts")));
    assert!(!is_example_like_path(Path::new("src/lib/sampler.ts")));
}
