import { ApiError, MAX_UPLOAD_BYTES } from "./http.js";
import type { UploadedFile } from "./files.js";

export type ParsedBody =
  | { kind: "json"; body: Record<string, unknown> }
  | { kind: "form"; form: FormData };

export async function readBody(request: Request): Promise<ParsedBody> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new ApiError(400, "INVALID_JSON", "The request body is not valid JSON.");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new ApiError(400, "INVALID_JSON", "The request body must be a JSON object.");
    }
    return { kind: "json", body: body as Record<string, unknown> };
  }
  if (contentType.includes("multipart/form-data")) {
    try {
      return { kind: "form", form: await request.formData() };
    } catch {
      throw new ApiError(400, "INVALID_FORM_DATA", "The multipart upload could not be read.");
    }
  }
  throw new ApiError(
    415,
    "UNSUPPORTED_CONTENT_TYPE",
    "Send application/json for text or multipart/form-data for file uploads.",
  );
}

export function requireText(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new ApiError(400, "EMPTY_TEXT", "Provide some text to scan.");
  }
  if (new TextEncoder().encode(value).byteLength > MAX_UPLOAD_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The text is larger than the 4 MB limit.");
  }
  return value;
}

export async function requireFile(form: FormData): Promise<UploadedFile> {
  const entry = form.get("file");
  if (!entry || typeof entry === "string") {
    throw new ApiError(400, "MISSING_FILE", "Attach a file in the \"file\" form field.");
  }
  if (entry.size > MAX_UPLOAD_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The file is larger than the 4 MB upload limit.");
  }
  const name = (entry.name || "upload").slice(0, 255);
  return { name, bytes: new Uint8Array(await entry.arrayBuffer()) };
}
