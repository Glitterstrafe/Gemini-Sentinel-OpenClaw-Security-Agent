
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  NEEDS_REVIEW = 'NEEDS_REVIEW',
}

export enum VulnerabilityCategory {
  SECURITY = 'Security Vulnerability',
  ABUSE = 'Abuse-Resistance',
  SAFETY = 'Safety/Data-Loss',
  RELIABILITY = 'Reliability/Correctness',
}

export interface Vulnerability {
  id: string;
  type: string;
  category: VulnerabilityCategory;
  severity: Severity;
  description: string;
  threatModel: string;
  preconditions: string;
  location: string;
  fix: string;
  explanation: string;
  filePath: string;
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
