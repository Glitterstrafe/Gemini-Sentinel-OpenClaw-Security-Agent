
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: Severity;
  description: string;
  location: string;
  fix: string;
  explanation: string;
  filePath: string; // New field to track which file the vulnerability is in
}

export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  summary: string;
  riskScore: number;
}

export interface StagedFile {
  name: string;
  path: string;
  content: string;
  size: number;
}
