use super::*;

fn scan(marker: &str, ai: bool) -> CodeScanReport {
    let temp = TempDir::new().unwrap();
    let handler = if ai {
        r#"import OpenAI from "openai";
export async function POST(req: Request) {
  const { prompt } = await req.json();
  return Response.json(await openai.chat.completions.create({ model, messages: [{ role: "user", content: prompt }] }));
}"#
    } else {
        r#"app.post("/auth/login", async (c) => c.json({ ok: true }));"#
    };
    write_file(
        temp.path(),
        "src/routes/chat.ts",
        &format!("{marker}\n{handler}"),
    );
    audit_project(temp.path()).unwrap()
}

#[test]
fn headers_and_comments_are_not_local_rate_limits() {
    let mut missing = Vec::new();
    for ai in [false, true] {
        let rule = if ai {
            "ai-rate-limit"
        } else {
            "public-endpoint-rate-limit"
        };
        let id = format!("{rule}:src/routes/chat.ts");
        for marker in [
            "res.headers.get(\"x-ratelimit-remaining\");",
            "res.headers.get('ratelimit-remaining');",
            "res.headers.get(`x-ratelimit-reset`);",
            "res.headers.get('X-ratelimit-remaining');",
            "res.headers.get('x-ratelimit-limit');",
            "res.headers.get('x-ratelimit-used');",
            "res.headers.get('x-ratelimit-remaining-requests');",
            "res.headers.get('x-ratelimit-limit-tokens');",
            "res.headers.get('ratelimit');",
            "res.headers.get('ratelimit-policy');",
            "res.headers.get('ratelimit-limit');",
            "res.headers.get('ratelimit-reset');",
            "res.headers.get('X-RateLimit-Bucket');",
            "res.headers.get('X-RateLimit-Global');",
            "res.headers.get('X-RateLimit-Scope');",
            "res.headers.get('x-ratelimit-resource');",
            "res.headers.get('x-rate-limit-limit');",
            "res.headers.get('x-rate-limit-remaining');",
            "res.headers.get('x-rate-limit-reset');",
            "// TODO: add rate limiting",
            "/* add rate limiting */",
            "/** rate-limit callers */",
        ] {
            let report = scan(marker, ai);
            if !report.issues.iter().any(|issue| issue.id == id) {
                missing.push(format!("{rule}: {marker}"));
            }
        }
        for marker in [
            "// x-ratelimit headers are upstream\nenv.MY_RATE_LIMITER.limit({ key: 'k' });",
            "SIGN_IN_RATE_LIMIT.limit({ key: 'k' });",
            "limiter.limit({ key: 'k' });",
            "import rateLimit from 'express-rate-limit';",
            "import { Ratelimit } from '@upstash/ratelimit';",
            "import { rateLimiter } from 'hono-rate-limiter';",
        ] {
            let report = scan(marker, ai);
            assert!(
                !report.issues.iter().any(|issue| issue.id == id),
                "{rule}: {marker}"
            );
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn upstream_limit_headers_are_not_evidence_in_header_accessors() {
    let mut missing = Vec::new();
    for ai in [false, true] {
        let rule = if ai {
            "ai-rate-limit"
        } else {
            "public-endpoint-rate-limit"
        };
        for name in [
            "X-RateLimit-Bucket",
            "X-RateLimit-Global",
            "X-RateLimit-Scope",
            "x-ratelimit-resource",
            "x-rate-limit-limit",
            "x-rate-limit-remaining",
            "x-rate-limit-reset",
            "ratelimit-policy",
        ] {
            for marker in [
                format!("res.headers.get(\"{name}\");"),
                format!("res.headers.has('{name}');"),
                format!("c.req.header(`{name}`);"),
                format!("res.getHeader('{name}');"),
                format!("res.headers['{name}'];"),
            ] {
                let report = scan(&marker, ai);
                if !report
                    .issues
                    .iter()
                    .any(|issue| issue.id == format!("{rule}:src/routes/chat.ts"))
                {
                    missing.push(format!("{rule}: {marker}"));
                }
            }
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn custom_counter_keys_remain_rate_limit_evidence() {
    let mut unexpected = Vec::new();
    for ai in [false, true] {
        let rule = if ai {
            "ai-rate-limit"
        } else {
            "public-endpoint-rate-limit"
        };
        for prefix in [
            "ratelimit-",
            "ratelimit-user:",
            "x-ratelimit-counter:",
            "ratelimit-policy-custom:",
            "x-ratelimit-limit",
            "ratelimit-limit",
        ] {
            let temp = TempDir::new().unwrap();
            let response = if ai {
                "return c.json(await openai.chat.completions.create({ model, messages: [] }));"
            } else {
                "return c.json({ ok: true });"
            };
            let import = if ai {
                "import OpenAI from 'openai';"
            } else {
                ""
            };
            write_file(
                temp.path(),
                "src/routes/chat.ts",
                &format!(
                    r#"{import}
app.post("/auth/login", async (c) => {{
  const ip = c.req.header("x-forwarded-for");
  const key = "{prefix}" + ip;
  const hits = await c.env.COUNTS.increment(key);
  if (hits > MAX) return c.text("slow down", 429);
  {response}
}});"#
                ),
            );
            let report = audit_project(temp.path()).unwrap();
            if report
                .issues
                .iter()
                .any(|issue| issue.id == format!("{rule}:src/routes/chat.ts"))
            {
                unexpected.push(format!("{rule}: {prefix}"));
            }
        }
    }
    assert!(unexpected.is_empty(), "{unexpected:?}");
}
