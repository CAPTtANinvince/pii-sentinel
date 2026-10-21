import { IMPLEMENTED_KINDS, SUPPORTED_EXTENSIONS } from "./_lib/files.js";
import { createHandler, json, MAX_UPLOAD_BYTES } from "./_lib/http.js";
import { providerConfiguration } from "./_lib/providers/index.js";

const handler = createHandler("/api/health", { methods: ["GET"] }, async (request, ctx) =>
  json(request, ctx, 200, {
    status: "ok",
    service: "pii-sentinel-api",
    timestamp: new Date().toISOString(),
    commit: process.env["VERCEL_GIT_COMMIT_SHA"]?.slice(0, 7) ?? null,
    limits: { maxUploadBytes: MAX_UPLOAD_BYTES },
    formats: {
      implemented: IMPLEMENTED_KINDS,
      planned: SUPPORTED_EXTENSIONS.filter((kind) => !IMPLEMENTED_KINDS.includes(kind)),
    },
    providers: providerConfiguration(),
  }),
);

export const GET = handler;
export const OPTIONS = handler;
