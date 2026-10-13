//! Portable SEO checks: sync page analysis plus the probe-verdict layer for
//! the origin-scoped robots.txt/sitemap fetches and the og:image probe.

pub mod canonical_meta;
pub mod content;
pub mod geo;
pub mod headings;
pub mod link_count;
pub mod links;
pub mod meta;
pub mod meta_refresh;
pub mod og_image;
pub mod parsing;
pub mod redirects;
pub mod robots;
pub mod robots_directives;
pub mod sitemap;
pub mod sitemap_document;
pub mod sitemap_walk;
pub mod speed_hints;
pub mod structured_data;
pub mod url_structure;
