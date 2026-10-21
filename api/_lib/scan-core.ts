import { CATEGORIES, type RiskLevel } from "./categories.js";
import type { ExtractedDocument } from "./files.js";
import { mergeDetections } from "./merge.js";
import { runProviders, type Engine } from "./providers/index.js";
import type { DetectionProvider } from "./providers/types.js";

export function maskValue(value: string): string {
  if (value.length <= 4) return "•".repeat(value.length);
  if (value.length <= 8) return `${value[0]}${"•".repeat(value.length - 2)}${value[value.length - 1]}`;
  return `${value.slice(0, 2)}${"•".repeat(Math.max(3, value.length - 6))}${value.slice(-4)}`;
}

export interface Finding {
  id: string;
  category: string;
  value: string;
  maskedValue: string;
  confidence: number;
  riskLevel: RiskLevel;
  explanation: string;
  recommendedAction: string;
  start: number;
  end: number;
  location: { start: number; end: number; page?: number; row?: number; column?: string };
  providers: string[];
}

export interface ScanResult {
  findings: Finding[];
  riskSummary: Record<RiskLevel, number>;
  providersUsed: string[];
  providersFailed: Array<{ provider: string; code: string }>;
  warnings: string[];
}

export async function scanDocument(
  doc: ExtractedDocument,
  engine: Engine,
  adapters?: DetectionProvider[],
): Promise<ScanResult> {
  const run = await runProviders(doc.text, doc.fields, engine, adapters);
  const merged = mergeDetections(run.detections);
  const riskSummary: Record<RiskLevel, number> = { high: 0, medium: 0, low: 0 };
  const findings = merged.map((detection, index): Finding => {
    const info = CATEGORIES[detection.category];
    const value = doc.text.slice(detection.start, detection.end);
    riskSummary[info.risk] += 1;
    return {
      id: `f-${String(index + 1).padStart(4, "0")}`,
      category: info.label,
      value,
      maskedValue: maskValue(value),
      confidence: Math.round(detection.confidence * 100) / 100,
      riskLevel: info.risk,
      explanation: info.explanation,
      recommendedAction: info.recommendedAction,
      start: detection.start,
      end: detection.end,
      location: { start: detection.start, end: detection.end, ...doc.locate(detection.start) },
      providers: detection.providers,
    };
  });
  return {
    findings,
    riskSummary,
    providersUsed: run.used,
    providersFailed: run.failed,
    warnings: run.warnings,
  };
}
