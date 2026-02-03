import { StagedFile } from "../types";

export interface RedactionSummary {
  totalMatches: number;
  filesWithMatches: number;
  patterns: string[];
}

interface RedactionPattern {
  name: string;
  regex: RegExp;
}

const REDACTION_PATTERNS: RedactionPattern[] = [
  {
    name: "Private Key Block",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    name: "AWS Access Key ID",
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    name: "AWS Session Key ID",
    regex: /ASIA[0-9A-Z]{16}/g,
  },
  {
    name: "AWS Secret Access Key",
    regex: /aws(.{0,20})?(secret|access)?(.{0,20})?key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
  },
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
  },
  {
    name: "GitHub Token",
    regex: /ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}/g,
  },
  {
    name: "Slack Token",
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  },
  {
    name: "Stripe Secret Key",
    regex: /sk_live_[0-9a-zA-Z]{16,}/g,
  },
  {
    name: "JWT",
    regex: /eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/g,
  },
  {
    name: "Generic Secret Assignment",
    regex: /(api|secret|token|password)[-_ ]?(key|token|secret|pwd)?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi,
  },
];

const labelFor = (name: string) => name.toUpperCase().replace(/[^A-Z0-9]+/g, "_");

export const redactSecrets = (
  files: StagedFile[],
): { files: StagedFile[]; summary: RedactionSummary } => {
  let totalMatches = 0;
  let filesWithMatches = 0;
  const patterns = new Set<string>();

  const redactedFiles = files.map((file) => {
    let content = file.content;
    let fileMatches = 0;

    for (const pattern of REDACTION_PATTERNS) {
      content = content.replace(pattern.regex, () => {
        totalMatches += 1;
        fileMatches += 1;
        patterns.add(pattern.name);
        return `[REDACTED:${labelFor(pattern.name)}]`;
      });
    }

    if (fileMatches > 0) {
      filesWithMatches += 1;
    }

    return {
      ...file,
      content,
    };
  });

  return {
    files: redactedFiles,
    summary: {
      totalMatches,
      filesWithMatches,
      patterns: Array.from(patterns),
    },
  };
};
