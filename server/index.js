import http from "node:http";
import path from "node:path";
import { readFile, stat } from "node:fs/promises";
import { GoogleGenAI, Type } from "@google/genai";

const PORT = Number(process.env.PORT || 8787);
const API_KEY = process.env.GEMINI_API_KEY || "";
const DIST_DIR = path.resolve(process.cwd(), "dist");

const MAX_BODY_BYTES = 7 * 1024 * 1024;
const MAX_FILE_COUNT = 300;
const MAX_FILE_SIZE_BYTES = 1024 * 1024;
const MAX_TOTAL_SIZE_BYTES = 6 * 1024 * 1024;

const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "img-src 'self' data:",
  "font-src 'self' https://fonts.gstatic.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "script-src 'self'",
  "connect-src 'self'",
].join("; ");

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
};

const setSecurityHeaders = (res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", CSP);
};

const sendJson = (res, status, payload) => {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("Payload too large."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });

const validateFiles = (files) => {
  if (!Array.isArray(files)) {
    throw new Error("Invalid payload: files must be an array.");
  }
  if (files.length > MAX_FILE_COUNT) {
    throw new Error("Too many files in a single request.");
  }

  let totalSize = 0;
  for (const file of files) {
    if (!file || typeof file !== "object") {
      throw new Error("Invalid file entry.");
    }
    if (typeof file.path !== "string" || typeof file.content !== "string") {
      throw new Error("Invalid file content.");
    }
    const size = typeof file.size === "number" ? file.size : Buffer.byteLength(file.content, "utf-8");
    if (size > MAX_FILE_SIZE_BYTES) {
      throw new Error(`File ${file.path} exceeds size limit.`);
    }
    totalSize += size;
    if (totalSize > MAX_TOTAL_SIZE_BYTES) {
      throw new Error("Total payload exceeds size limit.");
    }
  }
};

const buildPrompt = (formattedCode) => `You are Gemini Sentinel, a security analysis agent for autonomous and semi-autonomous code systems.

Your goal is to produce accurate, threat-model-driven security findings, not generic lint or reliability warnings.

Some content may be redacted as [REDACTED:TYPE]. Do not attempt to infer or reconstruct redacted data.

Please analyze the provided code with the following constraints:

1. Classify findings by type:
   - Security vulnerability
   - Abuse-resistance / cost-exhaustion risk
   - Safety / data-loss risk
   - Reliability / correctness issue

2. For each finding, you must determine:
   - Threat model: who could exploit this and how
   - Preconditions required for exploitation
   - Realistic impact
   - Evidence from code (line/function references)

3. SEVERITY RULES:
   Only label issues as HIGH or CRITICAL severity if they enable:
   - Remote code execution
   - Unauthorized file or network access
   - Privilege escalation
   - Data exfiltration
   - Cost-based denial-of-service by untrusted input

4. Avoid classifying purely internal reliability issues as security vulnerabilities.

5. When suggesting fixes:
   - Provide minimal diffs or concrete code snippets
   - Avoid placeholders or assumptions
   - Prefer architectural patterns when appropriate (sandboxing, allowlists, central wrappers)

6. Distinguish between Local-only developer tools and Future-deployable agents and adapt threat models accordingly.

7. If an issue is ambiguous, mark severity as 'NEEDS_REVIEW' rather than inflating severity.

CODE REPOSITORY TO ANALYZE:
${formattedCode}`;

const generateAnalysis = async (files) => {
  if (!API_KEY) {
    throw new Error("Server is missing GEMINI_API_KEY.");
  }
  const ai = new GoogleGenAI({ apiKey: API_KEY });
  const formattedCode = files
    .map((file) => `--- FILE: ${file.path} ---\n${file.content}`)
    .join("\n\n");

  const response = await ai.models.generateContent({
    model: "gemini-3-pro-preview",
    contents: buildPrompt(formattedCode),
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING },
          riskScore: { type: Type.NUMBER },
          vulnerabilities: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                id: { type: Type.STRING },
                type: { type: Type.STRING },
                category: {
                  type: Type.STRING,
                  enum: [
                    "Security Vulnerability",
                    "Abuse-Resistance",
                    "Safety/Data-Loss",
                    "Reliability/Correctness",
                  ],
                },
                severity: {
                  type: Type.STRING,
                  enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEEDS_REVIEW"],
                },
                description: { type: Type.STRING },
                threatModel: { type: Type.STRING },
                preconditions: { type: Type.STRING },
                location: { type: Type.STRING },
                filePath: { type: Type.STRING },
                fix: { type: Type.STRING },
                explanation: { type: Type.STRING },
              },
              required: [
                "id",
                "type",
                "category",
                "severity",
                "description",
                "threatModel",
                "preconditions",
                "location",
                "filePath",
                "fix",
                "explanation",
              ],
            },
          },
        },
        required: ["summary", "riskScore", "vulnerabilities"],
      },
      thinkingConfig: { thinkingBudget: 8000 },
    },
  });

  const text = response.text || "";
  if (!text) {
    throw new Error("Empty response from model.");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Model returned invalid JSON.");
  }
};

const serveStatic = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const requestedPath = decodeURIComponent(url.pathname);
  const safePath = requestedPath === "/" ? "/index.html" : requestedPath;
  const filePath = path.join(DIST_DIR, safePath);

  if (!filePath.startsWith(DIST_DIR)) {
    res.writeHead(400);
    res.end("Bad request.");
    return;
  }

  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) throw new Error("Not a file");
    const ext = path.extname(filePath);
    const contentType = CONTENT_TYPES[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(await readFile(filePath));
  } catch {
    try {
      const indexPath = path.join(DIST_DIR, "index.html");
      res.writeHead(200, { "Content-Type": CONTENT_TYPES[".html"] });
      res.end(await readFile(indexPath));
    } catch {
      res.writeHead(404);
      res.end("Not found.");
    }
  }
};

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && url.pathname === "/api/health") {
    return sendJson(res, 200, { status: "ok", hasKey: Boolean(API_KEY) });
  }

  if (req.method === "POST" && url.pathname === "/api/analyze") {
    try {
      const body = await readBody(req);
      const payload = JSON.parse(body || "{}");
      validateFiles(payload.files);
      const result = await generateAnalysis(payload.files);
      return sendJson(res, 200, result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Request failed.";
      return sendJson(res, 400, { error: message });
    }
  }

  if (req.method === "GET") {
    return serveStatic(req, res);
  }

  res.writeHead(405);
  res.end("Method not allowed.");
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Gemini Sentinel proxy listening on http://localhost:${PORT}`);
});
