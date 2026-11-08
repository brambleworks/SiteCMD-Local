import { describe, expect, it } from "vitest";
import { CODE_FIX_GUIDE_IDS, getCodeFixGuide } from "./code-fix-guides";
import { FIX_GUIDE_IDS, getFixGuide } from "./fix-guides";

const MAX_LEAD_LENGTH = 160;

function expectPlainLead(id: string, lead: string | undefined) {
  expect(lead, `${id} has no lead`).toBeTypeOf("string");
  const text = lead ?? "";
  expect(text.length, `${id} lead is ${text.length} characters`).toBeLessThan(MAX_LEAD_LENGTH);
  expect(text.length, `${id} lead is too short to explain anything`).toBeGreaterThanOrEqual(40);
  expect(text, `${id} lead must end as one sentence`).toMatch(/[.!?]$/);
  expect(text, `${id} lead must not carry code or fences`).not.toMatch(/`/);
  expect(text, `${id} lead must be one sentence`).not.toMatch(/[.!?]\s+[A-Z]/);
}

describe("every bundled fix guide opens with a plain-English lead", () => {
  it("describes gradients as blends of different colors", () => {
    // A gradient guide can still describe tonal brand fields as excessive gradient styling.
    const guide = getFixGuide("polish.gradient-backgrounds");
    expect(guide?.lead).toBe(
      "This page uses many gradients that blend different colors, which is worth a quick visual check.",
    );
    expect(guide?.steps[0]).toMatch(
      /^Review the multi-color gradients on the pages we list in the rendered design, not their number alone;/,
    );
  });

  it.each(FIX_GUIDE_IDS)("web guide %s", (id) => {
    expectPlainLead(id, getFixGuide(id)?.lead);
  });

  it.each(CODE_FIX_GUIDE_IDS)("code guide %s", (id) => {
    expectPlainLead(id, getCodeFixGuide(id)?.lead);
  });

  it("keeps the cited guides on their reviewed sentences", () => {
    expect(getFixGuide("security.https")?.lead).toBe(
      "Your site still answers over plain http://, so visitors can land on an unencrypted page.",
    );
    expect(getFixGuide("security.form_action_hijack")?.lead).toBe(
      "A form on your site sends what people type to another website, so make sure that destination is one you chose.",
    );
    expect(getFixGuide("performance.long_task_blocking")?.lead).toBe(
      "Something on the page keeps the browser busy for a long stretch, so taps and scrolls feel stuck.",
    );
    expect(getCodeFixGuide("suspicious-manifest-package")?.lead).toBe(
      "A package name in package.json looks like a typo of a popular library, which is how fake packages sneak in.",
    );
    expect(getCodeFixGuide("webhook-idempotency")?.lead).toBe(
      "Payment and webhook providers retry deliveries, so the same event must not be processed twice.",
    );
  });
});
