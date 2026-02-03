
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
}

export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  summary: string;
  riskScore: number;
}

export interface AgentStatus {
  name: string;
  status: 'IDLE' | 'ANALYZING' | 'PATCHING' | 'ERROR';
  lastAction: string;
}
