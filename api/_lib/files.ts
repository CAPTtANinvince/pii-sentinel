import { columnLetter, csvLayout, labelledLines } from "./fields.js";
import { ApiError, MAX_UPLOAD_BYTES } from "./http.js";
import type { LabelledField } from "./providers/types.js";

export const SUPPORTED_EXTENSIONS = ["pdf", "docx", "xlsx", "csv", "txt", "rtf", "eml", "msg"] as const;
export type FileKind = (typeof SUPPORTED_EXTENSIONS)[number];

/** Formats with a tested extractor. The rest return an honest 415 until their stage ships. */
export const IMPLEMENTED_KINDS: FileKind[] = ["txt", "csv"];

type Signature = "pdf" | "zip" | "ole" | "rtf" | "text" | "binary";

const EXPECTED_SIGNATURE: Record<FileKind, Signature> = {
  pdf: "pdf",
  docx: "zip",
  xlsx: "zip",
  msg: "ole",
  rtf: "rtf",
  csv: "text",
  txt: "text",
  eml: "text",
};

export interface UploadedFile {
  name: string;
  bytes: Uint8Array;
}

function startsWith(bytes: Uint8Array, signature: number[]): boolean {
  return signature.every((byte, index) => bytes[index] === byte);
}

function sniffSignature(bytes: Uint8Array): Signature {
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return "pdf";
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return "zip";
  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return "ole";
  const head = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? bytes.subarray(3) : bytes;
  if (startsWith(head, [0x7b, 0x5c, 0x72, 0x74, 0x66])) return "rtf";
  const sample = bytes.subarray(0, 8192);
  let control = 0;
  for (const byte of sample) {
    if (byte === 0) return "binary";
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20)) control += 1;
  }
  return control / Math.max(sample.length, 1) > 0.05 ? "binary" : "text";
}

export function fileExtension(name: string): string {
  const index = name.lastIndexOf(".");
  return index === -1 ? "" : name.slice(index + 1).toLowerCase();
}

/** Validate size, extension and file signature. Returns the format to extract. */
export function validateFile(file: UploadedFile): FileKind {
  if (file.bytes.byteLength === 0) throw new ApiError(400, "EMPTY_FILE", "The uploaded file is empty.");
  if (file.bytes.byteLength > MAX_UPLOAD_BYTES) {
    throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The file is larger than the 4 MB upload limit.");
  }
  const extension = fileExtension(file.name);
  if (!(SUPPORTED_EXTENSIONS as readonly string[]).includes(extension)) {
    throw new ApiError(
      415,
      "UNSUPPORTED_FILE_TYPE",
      `Unsupported file type. Supported: ${SUPPORTED_EXTENSIONS.join(", ").toUpperCase()}.`,
    );
  }
  const kind = extension as FileKind;
  if (sniffSignature(file.bytes) !== EXPECTED_SIGNATURE[kind]) {
    throw new ApiError(
      415,
      "FILE_SIGNATURE_MISMATCH",
      `The file content does not match the .${kind} extension, or the file is corrupted.`,
    );
  }
  if (!IMPLEMENTED_KINDS.includes(kind)) {
    throw new ApiError(
      415,
      "FORMAT_NOT_YET_SUPPORTED",
      `.${kind} files are not supported yet. Currently supported: ${IMPLEMENTED_KINDS.join(", ").toUpperCase()}.`,
    );
  }
  return kind;
}

function decodeText(bytes: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    text = new TextDecoder("windows-1252").decode(bytes);
  }
  return text.replace(/^\uFEFF/, "");
}

export interface ExtractedDocument {
  kind: FileKind | "text";
  text: string;
  fields: LabelledField[];
  /** Maps an offset to a page / row / column location when the format has one. */
  locate(offset: number): { page?: number; row?: number; column?: string };
}

export function documentFromText(text: string): ExtractedDocument {
  return { kind: "text", text, fields: labelledLines(text), locate: () => ({}) };
}

export function extractDocument(kind: FileKind, bytes: Uint8Array): ExtractedDocument {
  const text = decodeText(bytes);
  if (!text.trim()) throw new ApiError(400, "EMPTY_FILE", "The uploaded file contains no text.");
  if (kind === "csv") {
    const layout = csvLayout(text);
    return {
      kind,
      text,
      fields: layout.fields,
      locate(offset) {
        let low = 0;
        let high = layout.cells.length - 1;
        while (low < high) {
          const mid = (low + high + 1) >> 1;
          if (layout.cells[mid]!.start <= offset) low = mid;
          else high = mid - 1;
        }
        const cell = layout.cells[low];
        if (!cell || offset < cell.start || offset > cell.end) return {};
        const header = layout.headers[cell.columnIndex];
        return {
          row: cell.row,
          column: header ? `${columnLetter(cell.columnIndex)} (${header})` : columnLetter(cell.columnIndex),
        };
      },
    };
  }
  return { kind, text, fields: labelledLines(text), locate: () => ({}) };
}
