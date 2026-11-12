import type { FixGuideEntry } from "./types";

export const POLISH_FIX_GUIDES: Record<string, FixGuideEntry> = {
  "placeholder-text": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page shows placeholder content, such as sample text, a sample address or a stand-in image.",
    default: [
      "Open each page we list and look for sample text such as Lorem ipsum, sample addresses such as user@example.com, words in square or curly brackets, and images served by a placeholder image service. Replace each with real content or remove it.",
    ],
  },
  "dead-social-links": {
    effort: "quick",
    effortMinutes: 5,
    lead: "Some social icons on this page don't open a profile: they go nowhere or to the platform's home page.",
    default: [
      "On each page we list, click every social icon. Point each one that goes nowhere or to a platform's home page at your profile's full address, or remove the icon where you have no profile.",
    ],
  },
  "eyebrow-labels": {
    effort: "quick",
    effortMinutes: 10,
    lead: "Several headings on this page have a short label above them, which can repeat what the heading already says.",
    default: [
      "On each page we list, read every short label above a heading together with the heading. Remove labels that repeat the heading, and keep a label only where it adds something the heading does not say.",
    ],
  },
  "inline-style-density": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "A large share of this page's styling is written inline instead of reused, making a future visual change harder to apply.",
    default: [
      "Treat the count as a maintainability heuristic and inspect representative elements; runtime geometry, email-style output, CMS content, and intentionally inlined critical CSS can all make inline declarations appropriate. Move repeated static visual decisions into the project's existing classes, variables, or tokens, keep genuinely data-dependent values inline, and do not refactor unique working styles solely to lower the ratio.",
    ],
  },
  "tailwind-class-density": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "Some elements carry an unusually long string of utility classes, which can be hard for anyone to read and review.",
    default: [
      "Utility-first composition is a valid architecture, and class count alone does not establish duplication or poor maintainability. Extract only semantic recipes repeated across files, contradictory variants, or class strings reviewers routinely misunderstand into an existing component, variant helper, or named class per the project's conventions, preserving responsive, state, and dark-mode variants; keep clear one-off composition local.",
    ],
  },
  "no-css-architecture": {
    effort: "involved",
    effortMinutes: 30,
    lead: "This scan found no recognizable styling structure on this page, though a valid setup it cannot detect may still exist.",
    default: [
      "Load the page in a real browser and confirm its linked, imported, runtime-injected, and shadow-DOM styles loaded; the scan did not recognize a stylesheet or CSS-in-JS marker, which does not prove the project lacks styling architecture, so mark the finding reviewed when a valid system exists. If the page is genuinely unstyled, document one approach that fits the existing stack, reusing current components and tokens before adding a framework.",
    ],
  },
  "div-soup-ratio": {
    effort: "moderate",
    effortMinutes: 20,
    lead: "This page has a low ratio of semantic elements to generic containers, though plain containers are often the right choice.",
    default: [
      "Inspect the rendered regions behind the surfaced count; the ratio is a proxy, and div elements are correct for neutral layout containers. Use `<main>`, `<nav>`, `<section>`, and other native elements only where their documented semantics match, remove only wrappers with no layout, styling, or scripting role, and mark a high ratio reviewed when the remaining divs are intentionally neutral.",
    ],
  },
  "heading-hierarchy": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page's heading levels skip or repeat unexpectedly, so the structure needs a quick human review to confirm it is fine.",
    default: [
      "Compare the surfaced heading sequence with the rendered content structure; multiple h1 elements and level jumps are not automatically WCAG or SEO failures. Give the page a clear top-level heading, choose subsection levels from their real parent sections rather than visual size, use CSS for display text that does not label a section, and confirm the outline stays understandable when navigating by heading with a screen reader.",
    ],
  },
  "form-accessibility": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "A form control on this page has no proper accessible label, leaving a screen reader user unsure what it is for.",
    default: [
      "Inspect each surfaced control in the rendered accessibility tree first, since framework-generated IDs, shadow DOM, or runtime changes can alter the computed result. Give user-facing controls persistent visible labels connected by `for`/`id` or wrapping, using `aria-label` or `aria-labelledby` only when appropriate, then test keyboard entry and screen-reader names and fix the actual unnamed controls rather than refactoring labeled ones.",
    ],
  },
  "button-vs-clickable-div": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "A non-interactive element on this page has a click handler, so it may not work with a keyboard or screen reader by default.",
    default: [
      "Replace clickable `<div>`/`<span>` elements with `<button>`, which is keyboard-focusable, announced by screen readers, and responds to Enter/Space by default; use `<a href>` for navigation actions. If a custom element is unavoidable, implement its role, focusability, Enter/Space behavior, focus indicator, and accessible name, and test with keyboard and assistive technology; adding `role` alone does not reproduce native behavior.",
    ],
  },
  "missing-lang": {
    effort: "quick",
    effortMinutes: 1,
    lead: "This page's html tag has no language attribute, so a screen reader may guess the wrong pronunciation for its content.",
    default: [
      "Add a `lang` attribute to the `<html>` element using a valid BCP 47 tag for the primary content language, such as `en` for English or `es` for Spanish; not every language has an ISO 639-1 two-letter code. Add `lang` to any element whose content is in a different language.",
    ],
  },
  "gradient-backgrounds": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page uses many gradients that blend different colors, which is worth a quick visual check.",
    default: [
      "Review the multi-color gradients on the pages we list in the rendered design, not their number alone; gradients are a legitimate brand and data-visualization tool, and this heuristic cannot decide whether they are excessive. Consolidate accidental near-duplicates, remove only treatments that compete with content or make controls unclear, verify text contrast at the weakest points, and mark intentional treatments reviewed.",
    ],
  },
  glassmorphism: {
    effort: "quick",
    effortMinutes: 10,
    lead: "This page uses translucent, blurred panels over many backgrounds, which can hurt legibility if contrast is not checked.",
    default: [
      "Inspect the translucent, backdrop-blurred regions over every background they can cover; the pattern can be a deliberate brand treatment. Where blur weakens hierarchy or contrast, use a more opaque token, solid fallback, border, or shadow that preserves the grouping, then verify contrast, reduced-transparency and forced-colors modes, and unsupported-backdrop-filter behavior before keeping or changing the treatment.",
    ],
  },
  "scroll-animations": {
    effort: "quick",
    effortMinutes: 5,
    lead: "Content on this page depends on scroll-triggered animation to appear, which can leave it invisible if that script fails.",
    default: [
      "Run the page with slow and disabled JavaScript and confirm essential content remains available when an observer or animation library fails. Keep motion that communicates a real state change or spatial relationship, simplify decorative reveals that delay reading, and implement a targeted `prefers-reduced-motion: reduce` treatment instead of a universal `animation: none` reset that can break focus and loading signals.",
    ],
  },
  "excessive-border-radius": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page uses unusually large rounded corners across many elements, worth a quick check against your actual design intent.",
    default: [
      "Compare the surfaced radii with the product's design tokens; a large radius can be correct for pills, sheets, or a deliberate brand, and the threshold is an aesthetic heuristic, not a usability rule. Consolidate accidental near-duplicate values onto a small documented scale where that improves consistency, preserve shapes that communicate the component, and keep the design when the radii are intentional and coherent.",
    ],
  },
  "glow-shadows": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page uses an unusually high number of colored glow shadows, which is worth a quick visual sanity check.",
    default: [
      "Review each detected colored shadow in context; it may be intentional brand, focus, selection, or status emphasis, and color alone does not make a shadow unprofessional. Make state meaning clear without relying on glow alone, keep focus indicators distinguishable, consolidate repeated shadow recipes into tokens, and remove only glows that obscure edges or reduce contrast, testing light/dark themes and forced colors.",
    ],
  },
  "gradient-text": {
    effort: "quick",
    effortMinutes: 10,
    lead: "Some text on this page is filled with a gradient, which can be hard to read where its colors come close to the background.",
    default: [
      "On each page we list, find text whose color fades across its letters, often a large heading. Check its contrast at the lightest and darkest points against the background behind it, and use a solid color where any part is hard to read.",
    ],
  },
  "floating-blobs": {
    effort: "quick",
    effortMinutes: 3,
    lead: "This page contains several decorative floating shapes in the background, worth checking they are not distracting.",
    default: [
      "Confirm the surfaced absolutely positioned, blurred, or gradient shapes are decorative rather than meaningful illustrations, status indicators, or charts; this is a pattern heuristic. Keep decoration that supports the brand without competing with content, simplify repeated generic shapes that weaken hierarchy, hide decorative elements from the accessibility tree, and check overlap, contrast, and pointer interception.",
    ],
  },
  "em-dash-density": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page's text uses an unusually high number of em dashes, a pattern some readers now associate with generated writing.",
    default: [
      "Compare the flagged passages with the publication's editorial style; repeated em dashes are not evidence that text was AI-generated, and some writers use them deliberately. Revise only sentences where the punctuation creates ambiguity, repetitive cadence, or a brand-voice mismatch, have a human verify meaning and rhythm, and mark the finding reviewed when the usage is intentional.",
    ],
  },
  "ai-buzzword-dictionary": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "This page's copy has a high density of marketing buzzwords, which can sometimes read as vague to visitors.",
    default: [
      "Review each surfaced word in its sentence and product domain; a dictionary match is not proof of vague or AI-written copy, and terms such as cutting-edge can have a precise technical meaning. Replace a phrase only when it obscures the actual capability, constraint, or outcome, prefer a verified concrete description over an invented metric or promise, and have a product owner check factual claims.",
    ],
  },
  "ai-header-formulas": {
    effort: "quick",
    effortMinutes: 5,
    lead: "Some headings on this page follow a generic templated pattern that could just as easily describe a different product.",
    default: [
      "Review the surfaced headings in context; these templates are common in both human and generated marketing copy, so a match does not establish authorship or poor quality. Rewrite only a heading that could describe many unrelated products, naming the section's specific subject, audience, or verified outcome without adding claims the body cannot support, and keep an effective formula when it accurately labels the section.",
    ],
  },
  "inclusive-framing": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page's copy lists out many different audiences in a row, a pattern that can blur who it is actually written for.",
    default: [
      "Check the surfaced audience-enumeration phrase against actual customer segments; the construction is not evidence of AI authorship and can be accurate when the listed groups share a concrete need. If it blurs positioning, address the primary audience and outcome directly or give materially different groups their own examples or sections, and keep the wording when every group is real and the shared outcome is specific.",
    ],
  },
  "emoji-as-icons": {
    effort: "moderate",
    effortMinutes: 15,
    lead: "This page uses emoji characters as functional icons, which can render inconsistently and confuse assistive technology.",
    default: [
      "Determine whether each surfaced character is content, decoration, or a functional control; emoji rendering and spoken names vary by platform, but that does not make every use inappropriate. For a functional control, use a native text label or a tested icon component with a stable accessible name, hide purely decorative glyphs from assistive technology, and keep deliberate editorial or brand emoji where variation is acceptable.",
    ],
  },
  "three-column-grid": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page arranges content into a three-column grid, worth confirming the three items are actually comparable to each other.",
    default: [
      "Check whether the detected three-column group contains three genuinely comparable items; the layout is common because it can be effective and is not evidence of AI generation or low quality. If one item is primary or the items differ in complexity, express that hierarchy with ordering, span, typography, or progressive disclosure, and keep a uniform grid when comparison is the task.",
    ],
  },
  "default-page-title": {
    effort: "quick",
    effortMinutes: 2,
    lead: "This page's title is missing, empty, a framework default, or leftover placeholder text instead of your product's name.",
    default: [
      "Replace a missing, empty, or default `<title>` (such as 'Vite App', 'React App', or a bare 'Home') with a descriptive one like `<title>Your Product - What It Does</title>`, and set it in the root HTML template or layout component so every page gets a proper title.",
    ],
  },
  "missing-og-tags": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page's social preview tags are missing or incomplete, so a shared link may fall back to a weaker default preview.",
    default: [
      "Decide which social, chat, and link-preview destinations matter, then add accurate page-specific Open Graph title, description, canonical URL, type, and an absolute publicly fetchable image sized to each target platform's current requirements. Verify by fetching the page and image logged out and using current platform debuggers; missing tags do not mean the page is unfinished when link previews are out of scope.",
    ],
  },
  "default-favicon": {
    effort: "quick",
    effortMinutes: 3,
    lead: "This site's tab icon still appears to be the framework's default artwork rather than your own brand mark.",
    default: [
      "Open the icon URL from the finding and confirm it is still scaffold artwork, since filename matching is heuristic. If it is a default asset, create a simple recognizable mark that stays legible at small sizes, provide only the formats and sizes the product's supported browsers and install surfaces need, update the metadata or link declarations, and check tabs, bookmarks, and cached-icon refresh on the deployed site.",
    ],
  },
  "no-sitemap-robots": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page has no canonical link, robots directive, or sitemap reference, worth a deliberate check that the gap is intentional.",
    default: [
      "This heuristic only observed that the page markup contains no canonical link, robots meta directive, or sitemap link; none is universally required, and it did not request `/robots.txt`. Add a canonical only when the page needs a preferred URL signal and a robots directive only when behavior should differ from crawler defaults, or mark the finding reviewed when defaults are intentional; do not add inert metadata solely to clear the signal.",
    ],
  },
  "source-maps-production": {
    effort: "quick",
    effortMinutes: 10,
    lead: "A production file references a source map, and the scan saw only that reference; a reachable map would reveal original source.",
    default: [
      "Fetch the exact `sourceMappingURL` from the finding and inspect the final response; the scan saw only a reference, and a catch-all HTML response is not a source map. A public map is not automatically a vulnerability, but it makes bundled source and any accidental secrets easier to inspect, so decide whether that exposure is intentional. If browser access is unnecessary, switch to hidden maps uploaded to an access-controlled service, remove public references, and rotate anything exposed.",
    ],
  },
  "console-log-production": {
    effort: "quick",
    effortMinutes: 5,
    lead: "Debugging output appears to run on the live site, visible to any visitor who happens to open developer tools.",
    default: [
      "Run the production page to see which counted calls actually execute; a source match can be unreachable, environment-gated, or an intentional diagnostic. Remove obsolete debugging and any log that can reveal credentials, tokens, or personal data, route operational failures through the product's structured monitoring with redaction, and keep safe diagnostics with a defined support purpose rather than blanket-stripping every console method.",
    ],
  },
  "default-deployment-subdomain": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This site is being served from a hosting platform's default subdomain rather than a domain your brand controls.",
    default: [
      "Confirm whether the scanned URL is the public production site or an intentional preview, demo, or platform endpoint; a default subdomain is technically valid and not a quality defect in every context. If brand ownership and stable canonical URLs matter, connect a domain the organization controls using the hosting provider's current instructions, then verify DNS, certificates, redirects, cookies, and metadata before retiring the platform hostname.",
    ],
  },
  "boilerplate-html": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page still contains starter text or example content left over from the template it was originally built on.",
    default: [
      "Inspect every surfaced marker in the rendered page and its source; documentation, code examples, and harmless framework plumbing can match, so a phrase alone does not prove the page is a scaffold. Replace visitor-visible starter copy, placeholder links and assets, and unsupported claims with reviewed product content, preserve required runtime markers and licenses, and have a human reviewer confirm the experience is complete.",
    ],
  },
  "default-error-page": {
    effort: "quick",
    effortMinutes: 5,
    lead: "This page appears to show a generic framework error screen instead of a page your own site actually controls.",
    default: [
      "Inspect the marker and the scanned response first; the heuristic matched framework-like error text without proving which status, route, or framework produced it, and documentation can also contain a marker. If the response is an unintended default error state, replace it with a recovery page that preserves the correct HTTP status, gives visitors a safe explanation and useful navigation, and exposes no stack trace or internal detail, then verify unknown routes and controlled failures in production.",
    ],
  },
  "js-errors": {
    effort: "moderate",
    effortMinutes: 20,
    lead: "This page throws JavaScript errors while it loads, which can silently break features for anyone who visits it.",
    default: [
      "Reproduce the page with the same production URL, browser, consent state, and interactions the scan used, and correlate each error with its script and stack; extensions, blocked third parties, and transient networks can produce errors outside the app's control. Fix the earliest application-owned root cause and retest before assuming later errors are independent, and avoid suppressing `window.onerror` or promise rejections merely to clear the count.",
    ],
  },
};
