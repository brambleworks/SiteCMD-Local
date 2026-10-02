macro_rules! define_labels {
    ($($name:ident => $label:literal),+ $(,)?) => {
        $(pub(super) const $name: &str = $label;)+

        #[cfg(test)]
        pub(super) const ALL: &[&str] = &[$($name),+];
    };
}

define_labels! {
    NEXT_JS => "Next.js",
    EXPRESS_JS => "Express.js",
    PHP => "PHP",
    ASP_NET => "ASP.NET",
    NUXT_JS => "Nuxt.js",
    NEXT_JS_LIKELY => "Next.js (likely)",
    SVELTE_KIT => "SvelteKit",
    GATSBY => "Gatsby",
    REMIX => "Remix",
    ELEVENTY => "Eleventy",
    HUGO => "Hugo",
    JEKYLL => "Jekyll",
    HEXO => "Hexo",
    PELICAN => "Pelican",
    WORDPRESS => "WordPress",
    DRUPAL => "Drupal",
    SHOPIFY => "Shopify",
    SQUARESPACE => "Squarespace",
    WIX => "Wix",
    GHOST => "Ghost",
    WEBFLOW => "Webflow",
    CONTENTFUL => "Contentful",
    JOOMLA => "Joomla",
    REACT => "React",
    VUE_JS => "Vue.js",
    SVELTE => "Svelte",
    ANGULAR => "Angular",
    ASTRO => "Astro",
    ALPINE_JS => "Alpine.js",
    HTMX => "htmx",
    TAILWIND_CSS => "Tailwind CSS",
    BOOTSTRAP => "Bootstrap",
    BULMA => "Bulma",
    FOUNDATION => "Foundation",
    CHAKRA_UI => "Chakra UI",
    VERCEL => "Vercel",
    NETLIFY => "Netlify",
    CLOUDFRONT => "CloudFront",
    FASTLY => "Fastly",
    AKAMAI => "Akamai",
    CLOUDFLARE => "Cloudflare",
    GITHUB => "GitHub",
    AWS => "AWS",
    JQUERY => "jQuery",
}
