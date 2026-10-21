// Shared HTTP plumbing for every /api function: CORS, security headers,
// rate limiting, consistent JSON errors and content-free logging.

/** Upload limit. Vercel Functions reject request bodies above ~4.5 MB. */
export const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
/** Allowance for multipart boundaries and the JSON redaction payload. */
const REQUEST_OVERHEAD_BYTES = 256 * 1024;
export const MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + REQUEST_OVERHEAD_BYTES;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface RequestContext {
  requestId: string;
  route: string;
  /** Safe metadata only: never document content or detected values. */
  logMeta: Record<string, string | number | boolean | string[] | undefined>;
}

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Cache-Control": "no-store",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function envList(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function vercelHosts(): string[] {
  return [
    process.env["VERCEL_URL"],
    process.env["VERCEL_BRANCH_URL"],
    process.env["VERCEL_PROJECT_PRODUCTION_URL"],
  ].filter((host): host is string => Boolean(host));
}

/** Deployed Vercel domains, local development and ALLOWED_ORIGINS only. */
export function isAllowedOrigin(origin: string, requestHost: string | null): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const host = url.host;
  if (requestHost && host === requestHost) return true;
  if (url.hostname === "localhost" || url.hostname === "127.0.0.1") return true;
  if (url.protocol !== "https:") return false;
  if (vercelHosts().includes(host)) return true;
  if (host === "pii-sentinel.vercel.app") return true;
  if (/^pii-sentinel-[a-z0-9-]+-pii-sentinel1\.vercel\.app$/.test(host)) return true;
  return envList("ALLOWED_ORIGINS").some((allowed) => allowed.replace(/\/+$/, "") === url.origin);
}

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  if (!origin || !isAllowedOrigin(origin, request.headers.get("host"))) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    Vary: "Origin",
  };
}

export function json(
  request: Request,
  ctx: RequestContext,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Request-Id": ctx.requestId,
      ...SECURITY_HEADERS,
      ...corsHeaders(request),
      ...extraHeaders,
    },
  });
}

function errorResponse(request: Request, ctx: RequestContext, error: ApiError): Response {
  const headers: Record<string, string> = {};
  if (error.status === 429) headers["Retry-After"] = "60";
  return json(
    request,
    ctx,
    error.status,
    { error: error.message, code: error.code, requestId: ctx.requestId },
    headers,
  );
}

// Best-effort, per-instance fixed-window limiter. Vercel may run several
// instances, so this throttles bursts rather than enforcing a global quota.
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = Number(process.env["RATE_LIMIT_PER_MINUTE"] ?? 30);
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  return (
    forwarded?.split(",")[0]?.trim() || request.headers.get("x-real-ip") || "unknown"
  );
}

export function checkRateLimit(request: Request, route: string, now = Date.now()): void {
  const key = `${route}:${clientIp(request)}`;
  if (rateBuckets.size > 5000) {
    for (const [bucketKey, bucket] of rateBuckets) {
      if (bucket.resetAt <= now) rateBuckets.delete(bucketKey);
    }
  }
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return;
  }
  bucket.count += 1;
  if (bucket.count > RATE_LIMIT_MAX) {
    throw new ApiError(429, "RATE_LIMITED", "Too many requests. Please wait a minute and retry.");
  }
}

export function resetRateLimits(): void {
  rateBuckets.clear();
}

function log(ctx: RequestContext, method: string, status: number, startedAt: number): void {
  console.log(
    JSON.stringify({
      requestId: ctx.requestId,
      route: ctx.route,
      method,
      status,
      durationMs: Date.now() - startedAt,
      ...ctx.logMeta,
    }),
  );
}

interface HandlerOptions {
  methods: Array<"GET" | "POST">;
  rateLimit?: boolean;
}

type Handler = (request: Request, ctx: RequestContext) => Promise<Response>;

/** Wraps a route with CORS, method checks, rate limiting and error mapping. */
export function createHandler(route: string, options: HandlerOptions, handler: Handler) {
  return async function handle(request: Request): Promise<Response> {
    const startedAt = Date.now();
    const ctx: RequestContext = {
      requestId: request.headers.get("x-vercel-id")?.split("::").pop() ?? crypto.randomUUID(),
      route,
      logMeta: {},
    };
    let response: Response;
    try {
      const origin = request.headers.get("origin");
      if (origin && !isAllowedOrigin(origin, request.headers.get("host"))) {
        throw new ApiError(403, "ORIGIN_NOT_ALLOWED", "This origin is not allowed to call the API.");
      }
      if (request.method === "OPTIONS") {
        response = new Response(null, {
          status: 204,
          headers: { ...SECURITY_HEADERS, ...corsHeaders(request) },
        });
      } else if (!(options.methods as string[]).includes(request.method)) {
        throw new ApiError(405, "METHOD_NOT_ALLOWED", `Use ${options.methods.join(" or ")}.`);
      } else {
        if (options.rateLimit) checkRateLimit(request, route);
        const declaredLength = Number(request.headers.get("content-length") ?? 0);
        if (declaredLength > MAX_REQUEST_BYTES) {
          throw new ApiError(413, "PAYLOAD_TOO_LARGE", "The upload limit is 4 MB.");
        }
        response = await handler(request, ctx);
      }
    } catch (error) {
      if (error instanceof ApiError) {
        ctx.logMeta["code"] = error.code;
        response = errorResponse(request, ctx, error);
      } else {
        // Only the error class is logged: messages can quote parsed content.
        ctx.logMeta["code"] = "INTERNAL_ERROR";
        ctx.logMeta["errorName"] = error instanceof Error ? error.name : "unknown";
        response = errorResponse(
          request,
          ctx,
          new ApiError(500, "INTERNAL_ERROR", "Something went wrong while processing the request."),
        );
      }
    }
    log(ctx, request.method, response.status, startedAt);
    return response;
  };
}
