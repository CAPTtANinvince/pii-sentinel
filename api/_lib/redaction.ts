import { CATEGORIES, categoryKeyFromLabel } from "./categories.js";
import { ApiError } from "./http.js";
import { maskValue } from "./scan-core.js";

export type RedactionStrategy = "mask" | "replace" | "remove" | "custom";
const STRATEGIES: RedactionStrategy[] = ["mask", "replace", "remove", "custom"];
const MAX_FINDINGS = 10_000;
const MAX_REPLACEMENT_LENGTH = 64;

export interface RedactionTarget {
  start: number;
  end: number;
  category: string;
}

export function parseStrategy(raw: unknown): RedactionStrategy {
  if (typeof raw === "string" && (STRATEGIES as string[]).includes(raw)) return raw as RedactionStrategy;
  throw new ApiError(400, "INVALID_STRATEGY", `Strategy must be one of: ${STRATEGIES.join(", ")}.`);
}

export function parseReplacement(raw: unknown): string {
  if (raw === undefined || raw === null || raw === "") return "[REDACTED]";
  if (typeof raw !== "string") throw new ApiError(400, "INVALID_REPLACEMENT", "Replacement must be text.");
  // eslint-disable-next-line no-control-regex
  const cleaned = raw.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, MAX_REPLACEMENT_LENGTH);
  return cleaned || "[REDACTED]";
}

/**
 * Resolve the selected findings against the actual text. Offsets come from the
 * client, so each one is bounds-checked and, when a value is supplied, checked
 * against the text so a tampered or stale payload cannot redact the wrong span.
 */
export function resolveTargets(
  text: string,
  findingsRaw: unknown,
  selectedRaw: unknown,
): { targets: RedactionTarget[]; skipped: number } {
  if (!Array.isArray(findingsRaw) || findingsRaw.length > MAX_FINDINGS) {
    throw new ApiError(400, "INVALID_FINDINGS", "findings must be an array of scan findings.");
  }
  if (!Array.isArray(selectedRaw) || selectedRaw.length === 0) {
    throw new ApiError(400, "NO_SELECTION", "Select at least one finding to redact.");
  }
  const selected = new Set(selectedRaw.filter((id): id is string => typeof id === "string"));
  const targets: RedactionTarget[] = [];
  let skipped = 0;
  for (const raw of findingsRaw) {
    if (!raw || typeof raw !== "object") continue;
    const finding = raw as Record<string, unknown>;
    if (typeof finding["id"] !== "string" || !selected.has(finding["id"])) continue;
    const start = finding["start"];
    const end = finding["end"];
    const valid =
      Number.isInteger(start) &&
      Number.isInteger(end) &&
      (start as number) >= 0 &&
      (end as number) > (start as number) &&
      (end as number) <= text.length;
    const value = finding["value"];
    if (!valid || (typeof value === "string" && text.slice(start as number, end as number) !== value)) {
      skipped += 1;
      continue;
    }
    targets.push({
      start: start as number,
      end: end as number,
      category: typeof finding["category"] === "string" ? finding["category"] : "",
    });
  }
  if (targets.length === 0) {
    throw new ApiError(
      400,
      "STALE_FINDINGS",
      "None of the selected findings match this document. Scan it again and retry.",
    );
  }
  return { targets, skipped };
}

function substituteFor(
  original: string,
  category: string,
  strategy: RedactionStrategy,
  replacement: string,
): string {
  switch (strategy) {
    case "mask":
      return maskValue(original);
    case "replace": {
      const key = categoryKeyFromLabel(category);
      return `[${key ? CATEGORIES[key].replaceLabel : "REDACTED"}]`;
    }
    case "remove":
      return "";
    case "custom":
      return replacement;
  }
}

export interface RedactionOutcome {
  text: string;
  processedCount: number;
  verifiedValues: number;
}

export function applyRedaction(
  text: string,
  targets: RedactionTarget[],
  strategy: RedactionStrategy,
  replacement: string,
  options: { csv?: boolean } = {},
): RedactionOutcome {
  const spans = [...targets].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: RedactionTarget[] = [];
  for (const span of spans) {
    const previous = merged[merged.length - 1];
    if (previous && span.start < previous.end) previous.end = Math.max(previous.end, span.end);
    else merged.push({ ...span });
  }

  const originals = new Map<string, string>();
  for (const span of merged) {
    const original = text.slice(span.start, span.end);
    let substitute = substituteFor(original, span.category, strategy, replacement);
    if (options.csv) substitute = substitute.replace(/[",\r\n]/g, " ");
    originals.set(original, substitute);
  }

  for (const original of originals.keys()) {
    if (original.trim().length >= 3 && replacement.includes(original) && strategy === "custom") {
      throw new ApiError(400, "INVALID_REPLACEMENT", "The replacement text must not contain a redacted value.");
    }
  }

  let output = text;
  for (let i = merged.length - 1; i >= 0; i -= 1) {
    const span = merged[i]!;
    const substitute = originals.get(text.slice(span.start, span.end)) ?? "";
    output = output.slice(0, span.start) + substitute + output.slice(span.end);
  }

  // Remaining verbatim copies of a redacted value (e.g. in a signature line
  // the detector missed) are replaced too, then the result is verified.
  let verifiedValues = 0;
  for (const [original, substitute] of originals) {
    if (original.trim().length < 3) continue;
    output = output.split(original).join(substitute);
    if (output.includes(original)) {
      throw new ApiError(500, "REDACTION_VERIFY_FAILED", "Redaction could not be verified. Nothing was returned.");
    }
    verifiedValues += 1;
  }

  return { text: output, processedCount: merged.length, verifiedValues };
}
