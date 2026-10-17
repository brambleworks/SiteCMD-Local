//! Meta, Open Graph, viewport, and charset checks. The verdicts are the
//! engine's; this module keeps the og:image probe shell, which needs the
//! desktop's network policy and transport, and the tests that pin the
//! verdicts through the desktop's own check context.

pub use sitecmd_engine::checks::seo::meta::{
    CanonicalCheck, DuplicateMetaCheck, HreflangCheck, MetaCharsetCheck, MetaDescriptionCheck,
    NoindexCheck, OgImageAbsoluteCheck, OpenGraphCheck, TitleTagCheck, TwitterCardCheck,
    ViewportCheck,
};

mod og_resolvable;
pub use og_resolvable::OgImageResolvableCheck;

#[cfg(test)]
mod tests;
