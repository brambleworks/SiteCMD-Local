import { z } from "zod";
import type { IssueOccurrence } from "./db.js";

export const FIX_TARGET_SCHEMA = {
  relative_path: z
    .string()
    .min(1)
    .max(4096)
    .optional()
    .describe(
      "Exact Code Scan path from get_issue. Omit to let SiteCMD choose an occurrence; supply line if the path has multiple occurrences.",
    ),
  line: z
    .number()
    .int()
    .positive()
    .max(4294967295)
    .nullable()
    .optional()
    .describe(
      "Exact one-based Code Scan line from get_issue; null selects a finding without a line. Requires relative_path.",
    ),
};

/** Resolve a supplied location without falling back to another open occurrence. */
export function resolveFixTarget(
  occurrences: IssueOccurrence[],
  relativePath?: string,
  line?: number | null,
): { relativePath: string; line: number | null } | undefined {
  if (relativePath === undefined) {
    if (line !== undefined) throw new Error("line requires relative_path from get_issue.");
    return undefined;
  }
  const matches = occurrences.filter(
    (issue) =>
      issue.source === "code_scan" &&
      issue.relative_path === relativePath &&
      (line === undefined || (issue.line ?? null) === line),
  );
  if (matches.length === 0) {
    throw new Error(
      "No open Code Scan occurrence at that location; call get_issue for current locations.",
    );
  }
  if (matches.length !== 1) {
    throw new Error(
      "More than one open occurrence matches; call get_issue and supply an exact relative_path and line.",
    );
  }
  return { relativePath, line: matches[0].line ?? null };
}
