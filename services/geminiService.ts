import { AnalysisResult, StagedFile } from "../types";

interface ProxyErrorResponse {
  error?: string;
}

export class SecurityAgentService {
  async analyzeFiles(files: StagedFile[]): Promise<AnalysisResult> {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ files }),
    });

    if (!response.ok) {
      let message = `Proxy request failed (${response.status})`;
      try {
        const data = (await response.json()) as ProxyErrorResponse;
        if (data?.error) message = data.error;
      } catch {
        // ignore parse errors
      }
      throw new Error(message);
    }

    return (await response.json()) as AnalysisResult;
  }
}

export const securityAgent = new SecurityAgentService();
