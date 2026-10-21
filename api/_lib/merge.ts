import type { CategoryKey } from "./categories.js";
import type { Detection, ProviderId } from "./providers/types.js";

export interface MergedDetection {
  start: number;
  end: number;
  category: CategoryKey;
  confidence: number;
  providers: ProviderId[];
}

function overlaps(a: { start: number; end: number }, b: { start: number; end: number }) {
  return a.start < b.end && b.start < a.end;
}

/**
 * Merge detections from every provider into non-overlapping findings.
 * Same-category overlaps are unioned (providers combined, best confidence
 * kept); cross-category overlaps keep the more confident, then longer, span.
 */
export function mergeDetections(detections: Detection[]): MergedDetection[] {
  const ranked = [...detections].sort(
    (a, b) => b.confidence - a.confidence || b.end - b.start - (a.end - a.start),
  );
  const accepted: MergedDetection[] = [];
  for (const detection of ranked) {
    const clashing = accepted.filter((existing) => overlaps(existing, detection));
    if (clashing.length === 0) {
      accepted.push({ ...detection, providers: [detection.provider] });
      continue;
    }
    for (const existing of clashing) {
      if (existing.category !== detection.category) continue;
      existing.start = Math.min(existing.start, detection.start);
      existing.end = Math.max(existing.end, detection.end);
      if (!existing.providers.includes(detection.provider)) {
        existing.providers.push(detection.provider);
      }
    }
  }

  // Unions can grow into neighbours; resolve those in a final ordered pass.
  accepted.sort((a, b) => a.start - b.start || b.end - a.end);
  const result: MergedDetection[] = [];
  for (const current of accepted) {
    const previous = result[result.length - 1];
    if (!previous || !overlaps(previous, current)) {
      result.push(current);
      continue;
    }
    if (previous.category === current.category) {
      previous.end = Math.max(previous.end, current.end);
      previous.confidence = Math.max(previous.confidence, current.confidence);
      for (const provider of current.providers) {
        if (!previous.providers.includes(provider)) previous.providers.push(provider);
      }
    } else if (current.confidence > previous.confidence) {
      result[result.length - 1] = current;
    }
  }
  return result;
}
