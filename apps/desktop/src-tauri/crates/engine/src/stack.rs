//! Detects technology stacks from HTTP headers and HTML.
//!
//! The desktop, the CLI and the hosted runner's artifact run this one detector.

use serde::{Deserialize, Serialize};

#[path = "stack_labels.rs"]
mod labels;

#[path = "stack_hosting.rs"]
mod hosting;

pub use hosting::detect_hosting;

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
    /// The platform that serves the site, where an answer names it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosting: Option<String>,
    /// Whose nameservers answer for the site's domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_provider: Option<String>,
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
            && self.hosting.is_none()
            && self.dns_provider.is_none()
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
        if let Some(ref h) = self.hosting {
            parts.push(format!("Hosting: {}", h));
        }
        if let Some(ref d) = self.dns_provider {
            parts.push(format!("DNS: {}", d));
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
    detect_meta_generator(body, &mut stack);

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
    if let Some(powered) = crate::header_lines::field_value(headers, "x-powered-by") {
        let p = powered.to_lowercase();
        if p.contains("next.js") {
            stack.framework = Some(labels::NEXT_JS.into());
        } else if p.contains("express") {
            stack.framework = Some(labels::EXPRESS_JS.into());
        } else if p.contains("php") {
            stack.framework = Some(labels::PHP.into());
        } else if p.contains("asp.net") {
            stack.framework = Some(labels::ASP_NET.into());
        } else if p.contains("nuxt") {
            stack.framework = Some(labels::NUXT_JS.into());
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
        stack.cdn = Some(labels::VERCEL.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::NEXT_JS_LIKELY.into());
        }
    }
    if headers.contains_key("x-nf-request-id") || headers.contains_key("x-netlify-request-id") {
        stack.cdn = Some(labels::NETLIFY.into());
    }
    if let Some(via) = crate::header_lines::field_value(headers, "via") {
        let v = via.to_lowercase();
        if v.contains("cloudfront") {
            stack.cdn = Some(labels::CLOUDFRONT.into());
        }
        if v.contains("fastly") {
            stack.cdn = Some(labels::FASTLY.into());
        }
        if v.contains("akamai") {
            stack.cdn = Some(labels::AKAMAI.into());
        }
    }
    if (headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status"))
        && stack.cdn.is_none()
    {
        stack.cdn = Some(labels::CLOUDFLARE.into());
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
        stack.cdn = Some(labels::GITHUB.into());
    }
    if (headers.contains_key("x-amz-cf-id") || headers.contains_key("x-amz-request-id"))
        && stack.cdn.is_none()
    {
        stack.cdn = Some(labels::AWS.into());
    }

    // X-Generator
    if let Some(gen) = crate::header_lines::field_value(headers, "x-generator") {
        parse_generator(&gen, stack);
    }
}

fn detect_cms(lower: &str, stack: &mut DetectedStack) {
    if stack.cms.is_some() {
        return;
    }

    // Structural markers only: a brand word in copy, a customer logo, or a
    // link to a vendor is not evidence that this site runs on it.
    if lower.contains("wp-content/") || lower.contains("wp-includes/") {
        stack.cms = Some(labels::WORDPRESS.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::PHP.into());
        }
    } else if lower.contains("/sites/default/files")
        || lower.contains("drupal-settings-json")
        || lower.contains("data-drupal")
        || lower.contains("/core/misc/")
    {
        stack.cms = Some(labels::DRUPAL.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::PHP.into());
        }
    } else if lower.contains("cdn.shopify.com") || lower.contains("shopifycdn.com") {
        stack.cms = Some(labels::SHOPIFY.into());
    } else if lower.contains("squarespace") || lower.contains("sqsp.") {
        stack.cms = Some(labels::SQUARESPACE.into());
    } else if lower.contains("wix.com") || lower.contains("wixsite") {
        stack.cms = Some(labels::WIX.into());
    } else if lower.contains("ghost.org") || lower.contains("ghost.io") {
        stack.cms = Some(labels::GHOST.into());
    } else if lower.contains("data-wf-page")
        || lower.contains("data-wf-site")
        || lower.contains("website-files.com")
    {
        stack.cms = Some(labels::WEBFLOW.into());
    } else if lower.contains("ctfassets.net") || lower.contains("cdn.contentful.com") {
        stack.cms = Some(labels::CONTENTFUL.into());
    }
}

fn detect_js_framework(lower: &str, stack: &mut DetectedStack) {
    if stack.js_framework.is_some() {
        return;
    }

    // Order matters - more specific first
    if lower.contains("__next") || lower.contains("_next/static") || lower.contains("/_next/") {
        stack.js_framework = Some(labels::REACT.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::NEXT_JS.into());
        }
    } else if lower.contains("__nuxt") || lower.contains("/_nuxt/") {
        stack.js_framework = Some(labels::VUE_JS.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::NUXT_JS.into());
        }
    } else if lower.contains("__svelte") || lower.contains("__sveltekit") {
        stack.js_framework = Some(labels::SVELTE.into());
        if stack.framework.is_none() {
            stack.framework = Some(labels::SVELTE_KIT.into());
        }
    } else if ANGULAR_ATTRIBUTE_RE.is_match(lower) {
        stack.js_framework = Some(labels::ANGULAR.into());
    } else if lower.contains("data-reactroot")
        || lower.contains("data-react")
        || lower.contains("_reactlistening")
    {
        stack.js_framework = Some(labels::REACT.into());
    } else if lower.contains("data-v-") || lower.contains("vue.js") || lower.contains("__vue") {
        stack.js_framework = Some(labels::VUE_JS.into());
    } else if lower.contains("data-astro") || lower.contains("astro-") {
        stack.js_framework = Some(labels::ASTRO.into());
    } else if lower.contains("x-data") || lower.contains("alpine") {
        stack.js_framework = Some(labels::ALPINE_JS.into());
    } else if lower.contains("hx-get") || lower.contains("hx-post") || lower.contains("htmx") {
        stack.js_framework = Some(labels::HTMX.into());
    }
}

fn detect_css_framework(lower: &str, stack: &mut DetectedStack) {
    if stack.css_framework.is_some() {
        return;
    }

    // Check class names and common patterns
    if lower.contains("tailwind") || has_tailwind_classes(lower) {
        stack.css_framework = Some(labels::TAILWIND_CSS.into());
    } else if lower.contains("bootstrap") || lower.contains("class=\"container") {
        stack.css_framework = Some(labels::BOOTSTRAP.into());
    } else if lower.contains("bulma") {
        stack.css_framework = Some(labels::BULMA.into());
    } else if lower.contains("foundation") && lower.contains("zurb") {
        stack.css_framework = Some(labels::FOUNDATION.into());
    } else if lower.contains("chakra") {
        stack.css_framework = Some(labels::CHAKRA_UI.into());
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
        stack.other.push(labels::JQUERY.into());
    }
    if lower.contains("gatsby") || lower.contains("___gatsby") {
        if stack.framework.is_none() {
            stack.framework = Some(labels::GATSBY.into());
        }
        if stack.js_framework.is_none() {
            stack.js_framework = Some(labels::REACT.into());
        }
    }
    if lower.contains("remix") && lower.contains("__remix") && stack.framework.is_none() {
        stack.framework = Some(labels::REMIX.into());
        if stack.js_framework.is_none() {
            stack.js_framework = Some(labels::REACT.into());
        }
    }
    if (lower.contains("eleventy") || lower.contains("11ty")) && stack.framework.is_none() {
        stack.framework = Some(labels::ELEVENTY.into());
    }
}

/// The content of the page's `<meta name="generator">`: the CMS
/// reader and the hosting reader both read it.
fn generator_value(body: &str) -> Option<String> {
    // Find <meta name="generator" content="...">
    crate::checks::seo::parsing::extract_meta(body, "generator")
}

fn detect_meta_generator(body: &str, stack: &mut DetectedStack) {
    if let Some(value) = generator_value(body) {
        parse_generator(&value, stack);
    }
}

fn parse_generator(value: &str, stack: &mut DetectedStack) {
    let v = value.to_lowercase();
    if v.contains("wordpress") {
        stack.cms = Some(labels::WORDPRESS.into());
    } else if v.contains("drupal") {
        stack.cms = Some(labels::DRUPAL.into());
    } else if v.contains("joomla") {
        stack.cms = Some(labels::JOOMLA.into());
    } else if v.contains("hugo") {
        stack.framework = Some(labels::HUGO.into());
    } else if v.contains("jekyll") {
        stack.framework = Some(labels::JEKYLL.into());
    } else if v.contains("gatsby") {
        stack.framework = Some(labels::GATSBY.into());
    } else if v.contains("ghost") {
        stack.cms = Some(labels::GHOST.into());
    } else if v.contains("hexo") {
        stack.framework = Some(labels::HEXO.into());
    } else if v.contains("pelican") {
        stack.framework = Some(labels::PELICAN.into());
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
