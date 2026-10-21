import { documentFromText, extractDocument, validateFile, type ExtractedDocument } from "./_lib/files.js";
import { ApiError, createHandler, json } from "./_lib/http.js";
import { readBody, requireFile, requireText } from "./_lib/input.js";
import { applyRedaction, parseReplacement, parseStrategy, resolveTargets } from "./_lib/redaction.js";

function sanitizedName(name: string): string {
  const dot = name.lastIndexOf(".");
  const base = (dot > 0 ? name.slice(0, dot) : name).replace(/[^\w.-]+/g, "_").slice(0, 100);
  const ext = dot > 0 ? name.slice(dot) : ".txt";
  return `${base || "document"}.sanitized${ext}`;
}

const handler = createHandler("/api/redact", { methods: ["POST"], rateLimit: true }, async (request, ctx) => {
  const parsed = await readBody(request);
  let payload: Record<string, unknown>;
  let doc: ExtractedDocument;
  let fileName: string | undefined;

  if (parsed.kind === "json") {
    payload = parsed.body;
    doc = documentFromText(requireText(payload["text"]));
  } else {
    const rawPayload = parsed.form.get("payload");
    try {
      payload = typeof rawPayload === "string" ? (JSON.parse(rawPayload) as Record<string, unknown>) : {};
    } catch {
      throw new ApiError(400, "INVALID_JSON", "The payload field is not valid JSON.");
    }
    if (!payload || typeof payload !== "object") {
      throw new ApiError(400, "INVALID_JSON", "The payload field must be a JSON object.");
    }
    const file = await requireFile(parsed.form);
    ctx.logMeta["fileSize"] = file.bytes.byteLength;
    const kind = validateFile(file);
    doc = extractDocument(kind, file.bytes);
    fileName = file.name;
  }

  const strategy = parseStrategy(payload["strategy"]);
  const replacement = parseReplacement(payload["replacement"]);
  const { targets, skipped } = resolveTargets(doc.text, payload["findings"], payload["selectedFindingIds"]);
  const outcome = applyRedaction(doc.text, targets, strategy, replacement, { csv: doc.kind === "csv" });

  ctx.logMeta["fileType"] = doc.kind;
  ctx.logMeta["strategy"] = strategy;
  ctx.logMeta["processed"] = outcome.processedCount;

  const warnings =
    skipped > 0 ? [`${skipped} selected finding(s) no longer matched the document and were skipped.`] : [];

  return json(request, ctx, 200, {
    mode: "live",
    ...(fileName ? { fileName } : {}),
    fileType: doc.kind,
    strategy,
    processedCount: outcome.processedCount,
    sanitizedText: outcome.text,
    downloadFileName: fileName ? sanitizedName(fileName) : "pii-sentinel-sanitized.txt",
    verification: { passed: true, checkedValues: outcome.verifiedValues },
    warnings,
    ...(warnings.length > 0 ? { message: warnings.join(" ") } : {}),
  });
});

export const POST = handler;
export const GET = handler;
export const OPTIONS = handler;
