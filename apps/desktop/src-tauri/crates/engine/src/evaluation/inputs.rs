//! What every artifact runner reads.

use std::sync::OnceLock;

use crate::checks::polish::PolishContext;
use crate::checks::security::tls::TlsFacts;
use crate::evaluation::{BrowserFacts, NegotiatedProtocol};
use crate::header_lines::HeaderLines;
use crate::page::PageContext;

/// Shared input shape for every artifact runner.
pub struct EvaluationInputs<'a> {
    pub page: &'a PageContext,
    pub tls_facts: Option<&'a TlsFacts>,
    pub negotiated_protocol: Option<&'a NegotiatedProtocol>,
    pub browser_facts: Option<&'a BrowserFacts>,
    /// How the runtime handed over the page's header lines, for the readers
    /// whose verdict turns on where a joined line ended.
    pub header_lines: HeaderLines,
    /// The page as the polish signals read it, borrowing the body, built by
    /// the first polish runner so the rest share its lowercase. Never set by
    /// callers.
    #[doc(hidden)]
    pub polish: OnceLock<PolishContext<'a>>,
}
