use std::sync::LazyLock;

#[path = "local_outbound.rs"]
mod local_outbound;
pub(in crate::core::code_scan) use local_outbound::*;

pub(in crate::core::code_scan) static REQUEST_BODY_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"request\.json\s*\(").unwrap(),
            regex::Regex::new(r"req\.body\b").unwrap(),
            regex::Regex::new(r"request\.formData\s*\(").unwrap(),
            regex::Regex::new(r"await\s+request\.json").unwrap(),
            regex::Regex::new(r"await\s+req\.json").unwrap(),
            regex::Regex::new(r"json\.loads\s*\(").unwrap(),
            // Query-only PHP reads are not request-body handling.
            regex::Regex::new(r"\$_(?:POST|REQUEST)\s*\[").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"php://input").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\$request->(?:input|all|post|json|validated|safe)\s*\(")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

/// PHP superglobal presence checks that do not consume the input value.
/// These spans are removed before detecting request-body parsing.
pub(in crate::core::code_scan) static PHP_PRESENCE_CHECK_PATTERN: LazyLock<regex::Regex> =
    LazyLock::new(|| {
        regex::Regex::new(r"\b(?:empty|isset)\s*\(\s*\$_(?:POST|REQUEST)[^()]*\)")
            .expect("static PHP pattern regex") // allow-expect: compile-time literal regex
    });

pub(in crate::core::code_scan) static SERVER_ACTION_INPUT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![regex::Regex::new(
            r#"\b(?:formData|data|input|values)\.get\s*\(\s*["'`][A-Za-z0-9_.-]+["'`]\s*\)"#,
        )
        .unwrap()]
    });

pub(in crate::core::code_scan) static SOURCE_ENV_KEY_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        let compile = |source| {
            regex::Regex::new(source).expect("static source env key pattern") // allow-expect: source comes only from compile-time literal regexes below
        };
        vec![
            compile(r"process\.env\.([A-Z][A-Z0-9_]+)"),
            compile(r#"process\.env\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\]"#),
            compile(r"import\.meta\.env\.([A-Z][A-Z0-9_]+)"),
            compile(r#"import\.meta\.env\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\]"#),
            compile(r#"Deno\.env\.get\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(r#"std::env::var(?:_os)?\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(r#"(?:option_env!|env!)\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(r#"os\.getenv\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(
                r#"os\.environ(?:\.get\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)|\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\])"#,
            ),
            compile(r#"os\.Getenv\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(
                r#"ENV(?:\.fetch\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)|\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\])"#,
            ),
            compile(r#"System\.getenv\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(r#"Environment\.GetEnvironmentVariable\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
            compile(r#"env\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)"#),
        ]
    });

pub(in crate::core::code_scan) static VALIDATION_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bzod\b").unwrap(),
            regex::Regex::new(r"\bvalibot\b").unwrap(),
            regex::Regex::new(r"\byup\b").unwrap(),
            regex::Regex::new(r"\bsafeParse\s*\(").unwrap(),
            regex::Regex::new(r"\bparse\s*\(").unwrap(),
            regex::Regex::new(r"\bparseAsync\s*\(").unwrap(),
            regex::Regex::new(r"\bBaseModel\b").unwrap(),
            regex::Regex::new(r"\bpydantic\b").unwrap(),
            regex::Regex::new(r"\bvalidate\w*\s*\(").unwrap(),
            regex::Regex::new(r"request->validate\s*\(").unwrap(),
            regex::Regex::new(r"FormRequest").unwrap(),
            // PHP native, WordPress, and Laravel validation APIs.
            regex::Regex::new(r"\bfilter_var\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bfilter_input\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bsanitize_[a-z_]+\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"(?:validate|sanitize)_callback").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"Validator::make").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            // Match validating FormRequest subclasses, not the base Request type.
            regex::Regex::new(r"\b[A-Z][A-Za-z0-9]+Request\s+\$[A-Za-z_]")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            // NestJS: a typed `@Body()` parameter is validated by the global or
            // route-level ValidationPipe against its class-validator DTO.
            regex::Regex::new(r"@Body\s*\([^)]*\)\s*[A-Za-z_$][\w$]*\s*:\s*[A-Z]")
                .expect("static Nest body parameter regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bValidationPipe\b").expect("static Nest validation pipe regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bclass-validator\b").expect("static class-validator regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static OUTBOUND_HTTP_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bfetch\s*\(").unwrap(),
            regex::Regex::new(r"\baxios\.(get|post|put|patch|delete|request)\s*\(").unwrap(),
            regex::Regex::new(r"\bky\.(get|post|put|patch|delete)\s*\(").unwrap(),
            regex::Regex::new(r"\bgot\.(get|post|put|patch|delete)\s*\(").unwrap(),
            regex::Regex::new(r"\brequests\.(get|post|put|patch|delete)\s*\(").unwrap(),
            regex::Regex::new(r"\bhttpx\.(get|post|put|patch|delete)\s*\(").unwrap(),
            regex::Regex::new(r"\bstripe\.").unwrap(),
            regex::Regex::new(r"\bresend\.").unwrap(),
            regex::Regex::new(r"\bsendgrid\b").unwrap(),
            regex::Regex::new(r"\bmailgun\b").unwrap(),
            regex::Regex::new(r"\bpostmark\b").unwrap(),
            regex::Regex::new(r"\btwilio\b").unwrap(),
            // Concrete clients avoid prose matches from bare brand names.
        ]
    });

pub(in crate::core::code_scan) static OUTBOUND_HTTP_RETRY_SKIP_PATTERNS: LazyLock<
    Vec<regex::Regex>,
> = LazyLock::new(|| {
    vec![
        regex::Regex::new(r#"\bfetch\s*\(\s*["']/"#).unwrap(),
        regex::Regex::new(r#"\baxios\.(get|post|put|patch|delete)\s*\(\s*["']/"#).unwrap(),
    ]
});

#[path = "rate_limits.rs"]
mod rate_limits;
pub(in crate::core::code_scan) use rate_limits::*;

pub(in crate::core::code_scan) static PUBLIC_RISK_ENDPOINT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bauth\b").unwrap(),
            regex::Regex::new(r"\blogin\b").unwrap(),
            regex::Regex::new(r"\bsign[ -]?in\b").unwrap(),
            regex::Regex::new(r"\bsign[ -]?up\b").unwrap(),
            regex::Regex::new(r"\bregister\b").unwrap(),
            regex::Regex::new(r"\breset\b").unwrap(),
            regex::Regex::new(r"\bpassword\b").unwrap(),
            regex::Regex::new(r"\bsearch\b").unwrap(),
            regex::Regex::new(r"\bchat\b").unwrap(),
            regex::Regex::new(r"\bcontact\b").unwrap(),
            regex::Regex::new(r"\bfeedback\b").unwrap(),
            regex::Regex::new(r"\bnewsletter\b").unwrap(),
            regex::Regex::new(r"\bsubscribe\b").unwrap(),
            regex::Regex::new(r"\bupload\b").unwrap(),
            // Route names only: a bare `import` / `export` word matches every
            // ES module, so require the path, quoted-route, or compound-name
            // form. Hyphen and underscore keep `/api/data-import` and
            // `bulk_export` matching; the ES keyword is always preceded by a
            // line break or a space, which none of these classes admits.
            regex::Regex::new(r#"(?:^|[-_/"'`])import(?:[-_/."'`?]|$)"#).unwrap(),
            regex::Regex::new(r#"(?:^|[-_/"'`])export(?:[-_/."'`?]|$)"#).unwrap(),
            regex::Regex::new(r"\binvite\b").unwrap(),
            regex::Regex::new(r"\bcheckout\b").unwrap(),
            regex::Regex::new(r"\bpayment\b").unwrap(),
            regex::Regex::new(r"\bwebhook\b").unwrap(),
        ]
    });

/// Request-handler markers that turn a route-shaped path or a `route.ts`
/// basename into an actual route. Each entry pairs the marker with the phrase
/// that names it in evidence text. Matched against the original content: the
/// HTTP verb exports are case-sensitive, because every framework that uses them
/// requires the uppercase name and lowercasing first would read a React
/// component called `Post` as a route handler. The other markers carry `(?i)`
/// where the framework's own casing varies.
pub(in crate::core::code_scan) static ROUTE_HANDLER_MARKER_PATTERNS: LazyLock<
    Vec<(&'static str, regex::Regex)>,
> = LazyLock::new(|| {
    let compile = |label: &'static str, source: &str| {
        (
            label,
            regex::Regex::new(source).expect("static route handler marker regex"), // allow-expect: source comes only from the compile-time literals below
        )
    };
    vec![
        // Next.js App Router and SvelteKit: `export async function GET(...)`,
        // `export const POST = ...`.
        compile(
            "an exported HTTP verb handler",
            r"(?m)^[\t ]*export\s+(?:async\s+)?(?:function|const|let|var)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b",
        ),
        // Re-exported handlers: `export { handler as GET, handler as POST }`.
        compile(
            "a re-exported HTTP verb handler",
            r"(?s)export\s*\{[^}]{0,200}\bas\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b",
        ),
        // Destructured handlers: `export const { GET } = createFromSource(...)`.
        compile(
            "a destructured HTTP verb export",
            r"(?s)export\s+(?:const|let|var)\s*\{[^}]{0,200}\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b[^}]{0,200}\}\s*=",
        ),
        // Remix and React Router data routes. Lowercase, like the verbs above
        // are uppercase: a component called `Loader` is not a data route.
        compile(
            "an exported action or loader",
            r"(?m)^[\t ]*export\s+(?:async\s+)?(?:function|const|let|var)\s+(?:action|loader)\b",
        ),
        // Next.js Pages Router and Express-style default handlers.
        compile(
            "a default request-handler export",
            r"(?i)export\s+default\s+(?:async\s+)?function\s+handler\b",
        ),
        // The same router by way of a factory: `export default
        // defaultHandler({ GET: ... })`, `export default
        // defaultResponder(getHandler)`. The callee has to name the role, so a
        // default export of any other call is not a handler.
        compile(
            "a default handler-factory export",
            r"export\s+default\s+[A-Za-z0-9_$]*(?i:handler|responder)\s*\(",
        ),
        // NestJS, Flask, and FastAPI route decorators.
        compile(
            "a route decorator",
            r"(?i)@(?:[a-z_]\w*\.)?(?:get|post|put|patch|delete|options|head|all|route|controller)\s*\(",
        ),
        // Express, Hono, Elysia, and Fastify verb calls and mounts, each with a
        // path argument. The receiver class keeps `prisma.app.delete(` from
        // qualifying, and the quoted path keeps `app.use(cors())` out. `api` is
        // deliberately absent: it names the browser HTTP client far more often
        // than a server router.
        compile(
            "a router verb call",
            r#"(?im)(?:^|[;{}(,\s])[A-Za-z0-9_$]*(?:app|router|server|hono|elysia|fastify|route)\s*\.\s*(?:get|post|put|patch|delete|options|head|all|use)\s*\(\s*["'`/]"#,
        ),
    ]
});

/// Markers that identify a client-side data module or component. These files
/// live under `api/` and `routes/` directories in many project layouts but
/// never serve a request. Matched against lowercased content.
pub(in crate::core::code_scan) static CLIENT_MODULE_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\buse(?:query|mutation|infinitequery|suspensequery)\s*[(<]")
                .expect("static client module regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r#"(?m)^\s*["']use client["']"#).expect("static client module regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static UPLOAD_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r"\bformData\s*\(").unwrap(),
            regex::Regex::new(r"\bmultipart\b").unwrap(),
            regex::Regex::new(r"\bupload\b").unwrap(),
            regex::Regex::new(r"(?i)\bputobject\b").unwrap(),
            regex::Regex::new(r"\bPutObjectCommand\b").unwrap(),
            regex::Regex::new(r"\bS3Client\b").unwrap(),
            regex::Regex::new(r"\bstorage\.from\s*\(").unwrap(),
            regex::Regex::new(r"\bcreateSignedUploadUrl\b").unwrap(),
            regex::Regex::new(r"\buploadBytes\b").unwrap(),
            regex::Regex::new(r"\bBlob\b").unwrap(),
            regex::Regex::new(r"\bFile\b").unwrap(),
            regex::Regex::new(r"\$_FILES\b").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static UPLOAD_FILE_INPUT_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
        regex::Regex::new(
            r#"(?is)(?:formData|data|input|values)\.get\s*\(\s*["'`](?:file|image|avatar|document|attachment|blob|upload)["'`]\s*\)"#,
        )
        .unwrap(),
        regex::Regex::new(r#"(?is)\b(?:body|input|payload|params|query|data)\.(?:file|image|avatar|document|attachment|blob|upload)\b"#).unwrap(),
        // PHP: the upload superglobal and Laravel's file accessors.
        regex::Regex::new(r"\$_FILES\s*\[").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        regex::Regex::new(r"\$request->(?:file|hasFile)\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
    ]
    });

pub(in crate::core::code_scan) static UPLOAD_SIZE_GUARD_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r#"\b(?:file|blob|upload)\.size\b"#).unwrap(),
            regex::Regex::new(r#"\bMAX_[A-Z0-9_]*FILE[A-Z0-9_]*SIZE\b"#).unwrap(),
            regex::Regex::new(r#"\bmaxFileSize\b"#).unwrap(),
            regex::Regex::new(r#"\bmaxUploadSize\b"#).unwrap(),
            regex::Regex::new(r#"\bcontent-length\b"#).unwrap(),
            regex::Regex::new(r#"\bContent-Length\b"#).unwrap(),
            regex::Regex::new(r#"\bsize\s*[<>]=?\s*"#).unwrap(),
            // PHP upload sizes and WordPress limits.
            regex::Regex::new(r#"\[\s*['"]size['"]\s*\]"#).expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_max_upload_size\b").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            // Laravel FormRequest types carry upload validation.
            regex::Regex::new(r"\b[A-Z][A-Za-z0-9]+Request\s+\$[A-Za-z_]")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static UPLOAD_TYPE_GUARD_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r#"\b(?:file|blob|upload)\.type\b"#).unwrap(),
            regex::Regex::new(r#"\bmimeType?\b"#).unwrap(),
            regex::Regex::new(r#"\bcontentType\b"#).unwrap(),
            regex::Regex::new(r#"\ballowedMime"#).unwrap(),
            regex::Regex::new(r#"\ballowedTypes\b"#).unwrap(),
            regex::Regex::new(r#"\bstartsWith\s*\(\s*["'`](?:image|video|audio|application)/"#)
                .unwrap(),
            regex::Regex::new(r#"\bincludes\s*\(\s*(?:file|blob|upload)\.type"#).unwrap(),
            // PHP: reading the upload's type field, a real MIME sniff
            // (finfo / wp_check_filetype), or a Laravel mimes: rule.
            regex::Regex::new(r#"\[\s*['"]type['"]\s*\]"#).expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_check_filetype").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bfinfo_file\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bmimes?:[a-z]").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            // Laravel: FormRequest type hint - see the size-guard list.
            regex::Regex::new(r"\b[A-Z][A-Za-z0-9]+Request\s+\$[A-Za-z_]")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static STORAGE_WRITE_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
            regex::Regex::new(r#"(?i)\bputobject\b"#).unwrap(),
            regex::Regex::new(r#"\bPutObjectCommand\b"#).unwrap(),
            regex::Regex::new(r#"\bstorage\.from\s*\("#).unwrap(),
            regex::Regex::new(r#"\.upload(?:Data|Bytes)?\s*\("#).unwrap(),
            regex::Regex::new(r#"\bcreateSignedUploadUrl\b"#).unwrap(),
            regex::Regex::new(r#"\buploadBytes\b"#).unwrap(),
            // PHP: moving the uploaded temp file into place, the WordPress
            // upload helper, and Laravel's storage calls.
            regex::Regex::new(r"\bmove_uploaded_file\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"\bwp_handle_upload\s*\(").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
            regex::Regex::new(r"->store(?:As|Publicly|PubliclyAs)?\s*\(")
                .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        ]
    });

pub(in crate::core::code_scan) static USER_CONTROLLED_STORAGE_KEY_PATTERNS: LazyLock<
    Vec<regex::Regex>,
> = LazyLock::new(|| {
    vec![
        regex::Regex::new(
            r#"(?is)(?:key|path)\s*:\s*(?:body|input|payload|params|query|data)\.[A-Za-z0-9_]+"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)(?:key|path)\s*:\s*[^,\n]{0,220}(?:file|blob|upload)\.name"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)\.upload(?:Data|Bytes)?\s*\(\s*(?:body|input|payload|params|query|data)\.[A-Za-z0-9_]+"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)\.upload(?:Data|Bytes)?\s*\(\s*[^,\n]{0,220}(?:file|blob|upload)\.name"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)createSignedUploadUrl\s*\(\s*(?:body|input|payload|params|query|data)\.[A-Za-z0-9_]+"#,
        )
        .unwrap(),
        // PHP: destination path built from the client-supplied filename.
        // basename still counts - it stops traversal but not collisions,
        // overwrites, or attacker-chosen extensions, which is what this
        // check is about.
        regex::Regex::new(r#"(?s)\bmove_uploaded_file\s*\([^;]{0,240}\[\s*['"]name['"]\s*\]"#)
            .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        regex::Regex::new(r"(?s)->storeAs\s*\([^;]{0,160}getClientOriginalName").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
    ]
});

pub(in crate::core::code_scan) static SCOPED_STORAGE_KEY_PATTERNS: LazyLock<Vec<regex::Regex>> =
    LazyLock::new(|| {
        vec![
        regex::Regex::new(
            r#"(?is)(?:key|path)\s*:\s*[^,\n]{0,260}(?:userId|orgId|organizationId|teamId|workspaceId|tenantId|accountId|customerId|ownerId|session\.user\.[A-Za-z0-9_]+|ctx\.user\.[A-Za-z0-9_]+)"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)\.upload(?:Data|Bytes)?\s*\(\s*[^,\n]{0,260}(?:userId|orgId|organizationId|teamId|workspaceId|tenantId|accountId|customerId|ownerId|session\.user\.[A-Za-z0-9_]+|ctx\.user\.[A-Za-z0-9_]+)"#,
        )
        .unwrap(),
        regex::Regex::new(
            r#"(?is)createSignedUploadUrl\s*\(\s*[^,\n]{0,260}(?:userId|orgId|organizationId|teamId|workspaceId|tenantId|accountId|customerId|ownerId|session\.user\.[A-Za-z0-9_]+|ctx\.user\.[A-Za-z0-9_]+)"#,
        )
        .unwrap(),
        // PHP: destination scoped by the current WordPress user or by
        // Laravel's authenticated id.
        regex::Regex::new(r"(?s)\bmove_uploaded_file\s*\([^;]{0,240}get_current_user_id\s*\(")
            .expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
        regex::Regex::new(r"(?s)->store(?:As)?\s*\([^;]{0,200}auth\(\)->id").expect("static PHP pattern regex"), // allow-expect: compile-time literal regex
    ]
    });
