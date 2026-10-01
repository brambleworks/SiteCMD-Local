//! Detects technology stacks from HTTP headers and HTML.
//!
//! The desktop, the CLI and the hosted runner's artifact run this one detector.

use serde::{Deserialize, Serialize};

/// Technology stack detected from headers and HTML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectedStack {
    /// Web server (nginx, apache, cloudflare, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Server-side framework or runtime (express, php, asp.net, next.js, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// CMS (wordpress, drupal, shopify, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cms: Option<String>,
    /// Frontend JS framework (react, vue, angular, svelte, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub js_framework: Option<String>,
    /// CSS framework (tailwind, bootstrap, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub css_framework: Option<String>,
    /// CDN / hosting platform
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdn: Option<String>,
    /// Additional detected technologies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<String>,
}

impl DetectedStack {
    pub fn is_empty(&self) -> bool {
        self.server.is_none()
            && self.framework.is_none()
            && self.cms.is_none()
            && self.js_framework.is_none()
            && self.css_framework.is_none()
            && self.cdn.is_none()
            && self.other.is_empty()
    }

    /// Convert to a flat map for display and JSON serialization
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Human-readable summary for AI prompts
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref s) = self.server {
            parts.push(format!("Server: {}", s));
        }
        if let Some(ref f) = self.framework {
            parts.push(format!("Framework: {}", f));
        }
        if let Some(ref c) = self.cms {
            parts.push(format!("CMS: {}", c));
        }
        if let Some(ref j) = self.js_framework {
            parts.push(format!("JS: {}", j));
        }
        if let Some(ref c) = self.css_framework {
            parts.push(format!("CSS: {}", c));
        }
        if let Some(ref c) = self.cdn {
            parts.push(format!("CDN/Hosting: {}", c));
        }
        for o in &self.other {
            parts.push(o.clone());
        }
        if parts.is_empty() {
            "Unknown".into()
        } else {
            parts.join(", ")
        }
    }
}

/// `ng-app` or `ng-version` as a real attribute, in either the bare or the
/// HTML-valid `data-` form. A bare substring test read `ng-app` out of
/// `<meta name="govuk:publishing-app">`.
static ANGULAR_ATTRIBUTE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r#"[\s"'](?:data-)?ng-(?:app|version)(?:[\s=>"'/]|$)"#)
        .expect("static angular attribute regex") // allow-expect: compile-time literal regex
});

/// Detect the stack from headers and HTML; `lower` is the ASCII-lowercased body.
pub fn detect_stack(headers: &http::HeaderMap, body: &str, lower: &str) -> DetectedStack {
    let mut stack = DetectedStack::default();

    detect_from_headers(headers, &mut stack);

    detect_cms(lower, &mut stack);
    detect_js_framework(lower, &mut stack);
    detect_css_framework(lower, &mut stack);
    detect_other(lower, &mut stack);

    // Meta generator tag (catches many CMSs)
    detect_meta_generator(body, lower, &mut stack);

    stack
}

fn detect_from_headers(headers: &http::HeaderMap, stack: &mut DetectedStack) {
    // Server header
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        let s = server.to_lowercase();
        let name = if s.contains("nginx") {
            "Nginx"
        } else if s.contains("apache") {
            "Apache"
        } else if s.contains("cloudflare") {
            // "cloudflare" as Server header just means traffic is proxied -
            // the real origin server is hidden. Captured via cdn field instead.
            ""
        } else if s.contains("microsoft") || s.contains("iis") {
            "IIS"
        } else if s.contains("openresty") {
            "OpenResty"
        } else if s.contains("litespeed") {
            "LiteSpeed"
        } else if s.contains("caddy") {
            "Caddy"
        } else if s.contains("gunicorn") {
            "Gunicorn"
        } else if s.contains("uvicorn") {
            "Uvicorn"
        } else {
            server.split('/').next().unwrap_or(server)
        };
        if !name.is_empty() {
            stack.server = Some(name.to_string());
        }
    }

    // X-Powered-By
    if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        let p = powered.to_lowercase();
        if p.contains("next.js") {
            stack.framework = Some("Next.js".into());
        } else if p.contains("express") {
            stack.framework = Some("Express.js".into());
        } else if p.contains("php") {
            stack.framework = Some("PHP".into());
        } else if p.contains("asp.net") {
            stack.framework = Some("ASP.NET".into());
        } else if p.contains("nuxt") {
            stack.framework = Some("Nuxt.js".into());
        }
    }

    // CDN / Hosting detection from headers
    if headers.contains_key("x-vercel-id")
        || headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("Vercel"))
            .unwrap_or(false)
    {
        stack.cdn = Some("Vercel".into());
        if stack.framework.is_none() {
            stack.framework = Some("Next.js (likely)".into());
        }
    }
    if headers.contains_key("x-nf-request-id") || headers.contains_key("x-netlify-request-id") {
        stack.cdn = Some("Netlify".into());
    }
    if let Some(via) = headers.get("via").and_then(|v| v.to_str().ok()) {
        let v = via.to_lowercase();
        if v.contains("cloudfront") {
            stack.cdn = Some("CloudFront".into());
        }
        if v.contains("fastly") {
            stack.cdn = Some("Fastly".into());
        }
        if v.contains("akamai") {
            stack.cdn = Some("Akamai".into());
        }
    }
    if (headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status"))
        && stack.cdn.is_none()
    {
        stack.cdn = Some("Cloudflare".into());
    }
    // `Server: GitHub.com` is sent by github.com itself as well as by Pages,
    // so the observable fact is GitHub, not the Pages product.
    if headers.contains_key("x-github-request-id")
        || headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase().contains("github"))
            .unwrap_or(false)
    {
        stack.cdn = Some("GitHub".into());
    }
    if (headers.contains_key("x-amz-cf-id") || headers.contains_key("x-amz-request-id"))
        && stack.cdn.is_none()
    {
        stack.cdn = Some("AWS".into());
    }

    // X-Generator
    if let Some(gen) = headers.get("x-generator").and_then(|v| v.to_str().ok()) {
        parse_generator(gen, stack);
    }
}

fn detect_cms(lower: &str, stack: &mut DetectedStack) {
    if stack.cms.is_some() {
        return;
    }

    // Structural markers only: a brand word in copy, a customer logo, or a
    // link to a vendor is not evidence that this site runs on it.
    if lower.contains("wp-content/") || lower.contains("wp-includes/") {
        stack.cms = Some("WordPress".into());
        if stack.framework.is_none() {
            stack.framework = Some("PHP".into());
        }
    } else if lower.contains("/sites/default/files")
        || lower.contains("drupal-settings-json")
        || lower.contains("data-drupal")
        || lower.contains("/core/misc/")
    {
        stack.cms = Some("Drupal".into());
        if stack.framework.is_none() {
            stack.framework = Some("PHP".into());
        }
    } else if lower.contains("cdn.shopify.com") || lower.contains("shopifycdn.com") {
        stack.cms = Some("Shopify".into());
    } else if lower.contains("squarespace") || lower.contains("sqsp.") {
        stack.cms = Some("Squarespace".into());
    } else if lower.contains("wix.com") || lower.contains("wixsite") {
        stack.cms = Some("Wix".into());
    } else if lower.contains("ghost.org") || lower.contains("ghost.io") {
        stack.cms = Some("Ghost".into());
    } else if lower.contains("data-wf-page")
        || lower.contains("data-wf-site")
        || lower.contains("website-files.com")
    {
        stack.cms = Some("Webflow".into());
    } else if lower.contains("ctfassets.net") || lower.contains("cdn.contentful.com") {
        stack.cms = Some("Contentful".into());
    }
}

fn detect_js_framework(lower: &str, stack: &mut DetectedStack) {
    if stack.js_framework.is_some() {
        return;
    }

    // Order matters - more specific first
    if lower.contains("__next") || lower.contains("_next/static") || lower.contains("/_next/") {
        stack.js_framework = Some("React".into());
        if stack.framework.is_none() {
            stack.framework = Some("Next.js".into());
        }
    } else if lower.contains("__nuxt") || lower.contains("/_nuxt/") {
        stack.js_framework = Some("Vue.js".into());
        if stack.framework.is_none() {
            stack.framework = Some("Nuxt.js".into());
        }
    } else if lower.contains("__svelte") || lower.contains("__sveltekit") {
        stack.js_framework = Some("Svelte".into());
        if stack.framework.is_none() {
            stack.framework = Some("SvelteKit".into());
        }
    } else if ANGULAR_ATTRIBUTE_RE.is_match(lower) {
        stack.js_framework = Some("Angular".into());
    } else if lower.contains("data-reactroot")
        || lower.contains("data-react")
        || lower.contains("_reactlistening")
    {
        stack.js_framework = Some("React".into());
    } else if lower.contains("data-v-") || lower.contains("vue.js") || lower.contains("__vue") {
        stack.js_framework = Some("Vue.js".into());
    } else if lower.contains("data-astro") || lower.contains("astro-") {
        stack.js_framework = Some("Astro".into());
    } else if lower.contains("x-data") || lower.contains("alpine") {
        stack.js_framework = Some("Alpine.js".into());
    } else if lower.contains("hx-get") || lower.contains("hx-post") || lower.contains("htmx") {
        stack.js_framework = Some("htmx".into());
    }
}

fn detect_css_framework(lower: &str, stack: &mut DetectedStack) {
    if stack.css_framework.is_some() {
        return;
    }

    // Check class names and common patterns
    if lower.contains("tailwind") || has_tailwind_classes(lower) {
        stack.css_framework = Some("Tailwind CSS".into());
    } else if lower.contains("bootstrap") || lower.contains("class=\"container") {
        stack.css_framework = Some("Bootstrap".into());
    } else if lower.contains("bulma") {
        stack.css_framework = Some("Bulma".into());
    } else if lower.contains("foundation") && lower.contains("zurb") {
        stack.css_framework = Some("Foundation".into());
    } else if lower.contains("chakra") {
        stack.css_framework = Some("Chakra UI".into());
    } else if lower.contains("material-ui") || lower.contains("muibox") || lower.contains("css-") {
        // MUI uses css-* class prefixes but too many false positives - skip
    }
}

fn has_tailwind_classes(lower: &str) -> bool {
    // Tailwind utility classes are distinctive - look for multiple matches
    let tw_patterns = [
        " flex ",
        " grid ",
        " px-",
        " py-",
        " mt-",
        " mb-",
        " text-sm",
        " bg-",
        " items-center",
        " justify-",
        " rounded-",
        " space-",
    ];
    tw_patterns.iter().filter(|p| lower.contains(*p)).count() >= 3
}

fn detect_other(lower: &str, stack: &mut DetectedStack) {
    if lower.contains("jquery") || lower.contains("jquery.min.js") {
        stack.other.push("jQuery".into());
    }
    if lower.contains("gatsby") || lower.contains("___gatsby") {
        if stack.framework.is_none() {
            stack.framework = Some("Gatsby".into());
        }
        if stack.js_framework.is_none() {
            stack.js_framework = Some("React".into());
        }
    }
    if lower.contains("remix") && lower.contains("__remix") && stack.framework.is_none() {
        stack.framework = Some("Remix".into());
        if stack.js_framework.is_none() {
            stack.js_framework = Some("React".into());
        }
    }
    if (lower.contains("eleventy") || lower.contains("11ty")) && stack.framework.is_none() {
        stack.framework = Some("Eleventy".into());
    }
}

fn detect_meta_generator(body: &str, lower: &str, stack: &mut DetectedStack) {
    // Find <meta name="generator" content="...">
    if let Some(pos) = lower.find("name=\"generator\"") {
        let region_start = crate::checks::floor_char_boundary(body, pos.saturating_sub(200));
        let region_end = crate::checks::ceil_char_boundary(body, body.len().min(pos + 300));
        let region = &body[region_start..region_end];
        let region_lower = region.to_ascii_lowercase();
        if let Some(cp) = region_lower.find("content=\"") {
            let start = cp + 9;
            if let Some(end) = region_lower[start..].find('"') {
                let value = &region[start..start + end];
                parse_generator(value, stack);
            }
        }
    }
}

fn parse_generator(value: &str, stack: &mut DetectedStack) {
    let v = value.to_lowercase();
    if v.contains("wordpress") {
        stack.cms = Some("WordPress".into());
    } else if v.contains("drupal") {
        stack.cms = Some("Drupal".into());
    } else if v.contains("joomla") {
        stack.cms = Some("Joomla".into());
    } else if v.contains("hugo") {
        stack.framework = Some("Hugo".into());
    } else if v.contains("jekyll") {
        stack.framework = Some("Jekyll".into());
    } else if v.contains("gatsby") {
        stack.framework = Some("Gatsby".into());
    } else if v.contains("ghost") {
        stack.cms = Some("Ghost".into());
    } else if v.contains("hexo") {
        stack.framework = Some("Hexo".into());
    } else if v.contains("pelican") {
        stack.framework = Some("Pelican".into());
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
