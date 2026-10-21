import { beforeEach, describe, expect, it } from "vitest";
import { GET as health } from "../../api/health";
import { POST as redact } from "../../api/redact";
import { POST as scan, GET as scanGet } from "../../api/scan";
import { luhnValid } from "../../api/_lib/checksums";
import { resetRateLimits } from "../../api/_lib/http";

const SAMPLE = "Contact Jane at jane.doe@example.com or card 4111 1111 1111 1111.";

function jsonRequest(path: string, body: unknown, headers: Record<string, string> = {}) {
  return new Request(`https://pii.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", host: "pii.test", ...headers },
    body: JSON.stringify(body),
  });
}

beforeEach(() => resetRateLimits());

describe("checksums", () => {
  it("validates card numbers with Luhn", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
  });
});

describe("/api/health", () => {
  it("reports status without leaking secrets", async () => {
    const res = await health(new Request("https://pii.test/api/health", { headers: { host: "pii.test" } }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; providers: Record<string, unknown> };
    expect(body.status).toBe("ok");
    expect(JSON.stringify(body)).not.toMatch(/key|secret|credential/i);
  });
});

describe("/api/scan", () => {
  it("detects PII in pasted text and masks values", async () => {
    const res = await scan(jsonRequest("/api/scan", { text: SAMPLE }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      totalFindings: number;
      findings: Array<{ value: string; maskedValue: string; start: number; end: number }>;
    };
    expect(body.totalFindings).toBeGreaterThan(0);
    for (const finding of body.findings) {
      expect(finding.maskedValue).not.toBe(finding.value);
      expect(SAMPLE.slice(finding.start, finding.end)).toBe(finding.value);
    }
  });

  it("rejects wrong methods, empty text and unknown engines", async () => {
    expect((await scanGet(new Request("https://pii.test/api/scan"))).status).toBe(405);
    expect((await scan(jsonRequest("/api/scan", { text: "" }))).status).toBe(400);
    expect((await scan(jsonRequest("/api/scan", { text: SAMPLE, engine: "nope" }))).status).toBe(400);
  });

  it("rejects foreign origins", async () => {
    const res = await scan(jsonRequest("/api/scan", { text: SAMPLE }, { origin: "https://evil.example" }));
    expect(res.status).toBe(403);
  });

  it("rejects unsupported file types", async () => {
    const form = new FormData();
    form.append("file", new File(["MZ binary"], "malware.exe", { type: "application/octet-stream" }));
    const res = await scan(new Request("https://pii.test/api/scan", { method: "POST", body: form }));
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });
});

describe("/api/redact", () => {
  it("removes selected findings from the text", async () => {
    const scanned = (await (await scan(jsonRequest("/api/scan", { text: SAMPLE }))).json()) as {
      findings: Array<{ id: string }>;
    };
    const res = await redact(
      jsonRequest("/api/redact", {
        text: SAMPLE,
        strategy: "replace",
        findings: scanned.findings,
        selectedFindingIds: scanned.findings.map((f) => f.id),
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sanitizedText: string; verification: { passed: boolean } };
    expect(body.sanitizedText).not.toContain("jane.doe@example.com");
    expect(body.verification.passed).toBe(true);
  });
});
