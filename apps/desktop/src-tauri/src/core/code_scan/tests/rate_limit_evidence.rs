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
