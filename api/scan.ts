import { documentFromText, extractDocument, validateFile, type ExtractedDocument } from "./_lib/files.js";
import { createHandler, json } from "./_lib/http.js";
import { readBody, requireFile, requireText } from "./_lib/input.js";
import { parseEngine } from "./_lib/providers/index.js";
import { scanDocument } from "./_lib/scan-core.js";

const handler = createHandler("/api/scan", { methods: ["POST"], rateLimit: true }, async (request, ctx) => {
  const parsed = await readBody(request);
  let doc: ExtractedDocument;
  let fileName: string | undefined;
  let engineRaw: unknown;

  if (parsed.kind === "json") {
    engineRaw = parsed.body["engine"];
    const text = requireText(parsed.body["text"]);
    doc = documentFromText(text);
  } else {
    engineRaw = parsed.form.get("engine");
    const file = await requireFile(parsed.form);
    ctx.logMeta["fileSize"] = file.bytes.byteLength;
    const kind = validateFile(file);
    doc = extractDocument(kind, file.bytes);
    fileName = file.name;
  }

  const engine = parseEngine(engineRaw);
  ctx.logMeta["fileType"] = doc.kind;
  ctx.logMeta["engine"] = engine;

  const result = await scanDocument(doc, engine);
  ctx.logMeta["providers"] = result.providersUsed;
  ctx.logMeta["findings"] = result.findings.length;

  return json(request, ctx, 200, {
    scanId: ctx.requestId,
    mode: "live",
    ...(fileName ? { fileName } : {}),
    fileType: doc.kind,
    characters: doc.text.length,
    totalFindings: result.findings.length,
    riskSummary: result.riskSummary,
    findings: result.findings,
    providers: { used: result.providersUsed, failed: result.providersFailed },
    warnings: result.warnings,
    ...(result.warnings.length > 0 ? { message: result.warnings.join(" ") } : {}),
  });
});

export const POST = handler;
export const GET = handler;
export const OPTIONS = handler;
