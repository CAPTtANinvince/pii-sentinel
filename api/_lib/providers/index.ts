import { ApiError } from "../http.js";
import { rulesProvider } from "./rules.js";
import {
  ProviderError,
  type Detection,
  type DetectionProvider,
  type LabelledField,
  type ProviderId,
} from "./types.js";

export type Engine = "auto" | ProviderId;
export const ENGINES: Engine[] = ["auto", "rules", "sapling", "google-cloud", "presidio"];

const PROVIDER_TIMEOUT_MS = Number(process.env["PROVIDER_TIMEOUT_MS"] ?? 10_000);

/** Adapters implemented so far. Stages B-D register Sapling, Google Cloud and Presidio here. */
const ADAPTERS: DetectionProvider[] = [rulesProvider];

/** Whether each provider's server-side configuration is present (booleans only). */
export function providerConfiguration(): Record<ProviderId, { configured: boolean; implemented: boolean }> {
  const implemented = (id: ProviderId) => ADAPTERS.some((adapter) => adapter.id === id);
  return {
    rules: { configured: true, implemented: true },
    sapling: { configured: Boolean(process.env["SAPLING_API_KEY"]), implemented: implemented("sapling") },
    "google-cloud": {
      configured: Boolean(
        process.env["GOOGLE_CLOUD_PROJECT_ID"] && process.env["GOOGLE_APPLICATION_CREDENTIALS_JSON"],
      ),
      implemented: implemented("google-cloud"),
    },
    presidio: {
      configured: Boolean(process.env["PRESIDIO_ANALYZER_URL"]),
      implemented: implemented("presidio"),
    },
  };
}

export function parseEngine(raw: unknown): Engine {
  if (raw === undefined || raw === null || raw === "") return "auto";
  if (typeof raw === "string" && (ENGINES as string[]).includes(raw)) return raw as Engine;
  throw new ApiError(400, "INVALID_ENGINE", `Unknown engine. Use one of: ${ENGINES.join(", ")}.`);
}

export interface ProviderRun {
  detections: Detection[];
  used: ProviderId[];
  failed: Array<{ provider: ProviderId; code: string }>;
  warnings: string[];
}

function selectProviders(engine: Engine, warnings: string[]): DetectionProvider[] {
  const available = ADAPTERS.filter((adapter) => adapter.isConfigured());
  if (engine === "auto") return available;
  const chosen = available.find((adapter) => adapter.id === engine);
  if (chosen) return [chosen];
  warnings.push(
    `The ${engine} provider is not available on this deployment; results come from the built-in rules.`,
  );
  return [rulesProvider];
}

/** Run providers in parallel with per-provider timeouts. Partial failure yields warnings. */
export async function runProviders(
  text: string,
  fields: LabelledField[],
  engine: Engine,
  adapters?: DetectionProvider[],
): Promise<ProviderRun> {
  const warnings: string[] = [];
  const providers = adapters ?? selectProviders(engine, warnings);
  const settled = await Promise.allSettled(
    providers.map((provider) =>
      provider.detect(text, { signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS), fields }),
    ),
  );

  const run: ProviderRun = { detections: [], used: [], failed: [], warnings };
  settled.forEach((outcome, index) => {
    const provider = providers[index]!;
    if (outcome.status === "fulfilled") {
      run.used.push(provider.id);
      run.detections.push(...outcome.value);
      return;
    }
    const reason = outcome.reason;
    const code =
      reason instanceof ProviderError
        ? reason.code
        : reason instanceof Error && (reason.name === "TimeoutError" || reason.name === "AbortError")
          ? "TIMEOUT"
          : "PROVIDER_ERROR";
    run.failed.push({ provider: provider.id, code });
    warnings.push(`${provider.label} was unavailable (${code}); results may be incomplete.`);
  });

  if (run.used.length === 0) {
    throw new ApiError(502, "PROVIDERS_UNAVAILABLE", "No detection provider could process the request.");
  }
  return run;
}
