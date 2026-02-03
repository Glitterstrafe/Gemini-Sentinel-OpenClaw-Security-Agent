
import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, Severity } from "../types";

export class SecurityAgentService {
  private ai: GoogleGenAI;

  constructor() {
    this.ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });
  }

  async analyzeCode(code: string): Promise<AnalysisResult> {
    const response = await this.ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: `Analyze the following code for security vulnerabilities. Be thorough and consider common pitfalls like SQL injection, XSS, insecure dependencies, and logic flaws. 
      
      Code to analyze:
      \`\`\`
      ${code}
      \`\`\``,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: { type: Type.STRING },
            riskScore: { type: Type.NUMBER, description: "0 to 100 risk score" },
            vulnerabilities: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  type: { type: Type.STRING },
                  severity: { 
                    type: Type.STRING, 
                    description: "CRITICAL, HIGH, MEDIUM, or LOW" 
                  },
                  description: { type: Type.STRING },
                  location: { type: Type.STRING },
                  fix: { type: Type.STRING, description: "The corrected code snippet" },
                  explanation: { type: Type.STRING }
                },
                required: ["id", "type", "severity", "description", "location", "fix", "explanation"]
              }
            }
          },
          required: ["summary", "riskScore", "vulnerabilities"]
        },
        thinkingConfig: { thinkingBudget: 4000 }
      },
    });

    const result = JSON.parse(response.text || '{}');
    return result as AnalysisResult;
  }
}

export const securityAgent = new SecurityAgentService();
