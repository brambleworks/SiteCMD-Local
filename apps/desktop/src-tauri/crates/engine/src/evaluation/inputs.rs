//! What every artifact runner reads.

use crate::checks::security::tls::TlsFacts;
use crate::evaluation::BrowserFacts;
use crate::header_lines::HeaderLines;
use crate::page::PageContext;

/// Shared input shape for every artifact runner.
pub struct EvaluationInputs<'a> {
    pub page: &'a PageContext,
    pub tls_facts: Option<&'a TlsFacts>,
    pub browser_facts: Option<&'a BrowserFacts>,
    /// How the runtime handed over the page's header lines, for the readers
    /// whose verdict turns on where a joined line ended.
    pub header_lines: HeaderLines,
}
