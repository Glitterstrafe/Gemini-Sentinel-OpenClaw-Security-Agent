
import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, StagedFile } from "../types";

export class SecurityAgentService {
  async analyzeFiles(files: StagedFile[], apiKey: string): Promise<AnalysisResult> {
    const trimmedKey = apiKey.trim();
    if (!trimmedKey) {
      throw new Error("Missing API key. Please provide a Gemini API key.");
    }

    const ai = new GoogleGenAI({ apiKey: trimmedKey });

    const formattedCode = files
      .map((file) => `--- FILE: ${file.path} ---\n${file.content}`)
      .join("\n\n");

    const prompt = `You are Gemini Sentinel, a security analysis agent for autonomous and semi-autonomous code systems.

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

    const response = await ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: prompt,
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
                  threatModel: { type: Type.STRING, description: "Who could exploit this and how" },
                  preconditions: { type: Type.STRING, description: "Required state for exploitation" },
                  location: { type: Type.STRING, description: "Specific line or function" },
                  filePath: {
                    type: Type.STRING,
                    description: "The relative path of the file containing this issue",
                  },
                  fix: { type: Type.STRING, description: "The corrected code snippet (minimal diff)" },
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
      throw new Error("Empty response from the model.");
    }

    try {
      return JSON.parse(text) as AnalysisResult;
    } catch (error) {
      throw new Error("Model returned invalid JSON. Please retry the analysis.");
    }
  }
}

export const securityAgent = new SecurityAgentService();

