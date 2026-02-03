
import { GoogleGenAI, Type } from "@google/genai";
import { AnalysisResult, StagedFile } from "../types";

export class SecurityAgentService {
  private ai: GoogleGenAI;

  constructor() {
    this.ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });
  }

  async analyzeFiles(files: StagedFile[]): Promise<AnalysisResult> {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });
    
    // Format files for the prompt
    const formattedCode = files.map(f => `--- FILE: ${f.path} ---\n${f.content}`).join('\n\n');

    const response = await ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: `Analyze the following source code files for security vulnerabilities. 
      You are an autonomous security agent (Sentinel) part of the OpenClaw initiative.
      Be thorough, look for cross-file vulnerabilities, data leaks, and common logic flaws.
      
      CODE REPOSITORY TO ANALYZE:
      ${formattedCode}`,
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
                  severity: { type: Type.STRING },
                  description: { type: Type.STRING },
                  location: { type: Type.STRING, description: "Specific line or function" },
                  filePath: { type: Type.STRING, description: "The relative path of the file containing this issue" },
                  fix: { type: Type.STRING, description: "The corrected code snippet" },
                  explanation: { type: Type.STRING }
                },
                required: ["id", "type", "severity", "description", "location", "filePath", "fix", "explanation"]
              }
            }
          },
          required: ["summary", "riskScore", "vulnerabilities"]
        },
        thinkingConfig: { thinkingBudget: 8000 }
      },
    });

    const result = JSON.parse(response.text || '{}');
    return result as AnalysisResult;
  }
}

export const securityAgent = new SecurityAgentService();
