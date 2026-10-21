import type { CategoryKey } from "../categories.js";

export type ProviderId = "rules" | "sapling" | "google-cloud" | "presidio";

/** A labelled region of the input, e.g. "Date of birth: <value>" or a CSV cell under a header. */
export interface LabelledField {
  label: string;
  start: number;
  end: number;
}

export interface DetectContext {
  signal: AbortSignal;
  fields: LabelledField[];
}

/** One provider's raw detection, already normalized to a PII category. */
export interface Detection {
  start: number;
  end: number;
  category: CategoryKey;
  confidence: number;
  provider: ProviderId;
}

export interface DetectionProvider {
  id: ProviderId;
  label: string;
  isConfigured(): boolean;
  detect(text: string, ctx: DetectContext): Promise<Detection[]>;
}

/** Thrown by adapters for upstream failures; the code (never content) is reported. */
export class ProviderError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
