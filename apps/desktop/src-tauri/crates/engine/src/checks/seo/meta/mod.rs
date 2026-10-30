//! Head metadata checks: the document's title, description, canonical,
//! viewport, charset, robots directives, social cards and hreflang
//! annotations, and head elements a page repeats. Each reads the served
//! document and nothing else, so every runtime grades it from one page.

pub(crate) use crate::checks::seo::parsing::{extract_attr_value, extract_meta};

mod charset;
mod duplicates;
mod head;
mod hreflang;
mod noindex;
mod og_absolute_urls;
mod social;
mod text;

pub use charset::MetaCharsetCheck;
pub use duplicates::DuplicateMetaCheck;
pub use head::{CanonicalCheck, ViewportCheck};
pub use hreflang::HreflangCheck;
pub use noindex::NoindexCheck;
pub use og_absolute_urls::OgImageAbsoluteCheck;
pub use social::{OpenGraphCheck, TwitterCardCheck};
pub use text::LengthOutcome;
pub(crate) use text::{description_outcome, description_value, title_outcome, title_value};
pub use text::{MetaDescriptionCheck, TitleTagCheck};
