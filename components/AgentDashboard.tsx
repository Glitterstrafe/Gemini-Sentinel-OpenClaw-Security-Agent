import React, { useEffect, useMemo, useRef, useState } from 'react';
import { securityAgent } from '../services/geminiService';
import { AnalysisResult, Severity, StagedFile, Vulnerability } from '../types';
import { redactSecrets, RedactionSummary } from '../services/secretSanitizer';
import VulnerabilityCard from './VulnerabilityCard';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const MAX_FILE_COUNT = 300;
const MAX_FILE_SIZE_BYTES = 1024 * 1024;
const MAX_TOTAL_SIZE_BYTES = 6 * 1024 * 1024;

const IGNORED_PATH_SEGMENTS = [
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
  '.next',
  'out',
];

const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /\.env(\.|$)/i,
  /id_rsa/i,
  /\.pem$/i,
  /\.key$/i,
  /\.pfx$/i,
  /\.p12$/i,
  /\.kdbx$/i,
  /secrets?\./i,
];

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const AgentDashboard: React.FC = () => {
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [appliedFixes, setAppliedFixes] = useState<Set<string>>(new Set());
  const [notification, setNotification] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState(() => {
    if (typeof window === 'undefined') return '';
    return sessionStorage.getItem('gemini_api_key') || '';
  });
  const [showApiKey, setShowApiKey] = useState(false);
  const [rememberKey, setRememberKey] = useState(() => {
    if (typeof window === 'undefined') return false;
    return Boolean(sessionStorage.getItem('gemini_api_key'));
  });
  const [redactEnabled, setRedactEnabled] = useState(true);
  const [allowSensitiveFiles, setAllowSensitiveFiles] = useState(false);
  const [allowUnredactedSecrets, setAllowUnredactedSecrets] = useState(false);
  const [redactionSummary, setRedactionSummary] = useState<RedactionSummary | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const totalSize = useMemo(
    () => stagedFiles.reduce((sum, file) => sum + file.size, 0),
    [stagedFiles],
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (rememberKey && apiKey.trim()) {
      sessionStorage.setItem('gemini_api_key', apiKey.trim());
    } else {
      sessionStorage.removeItem('gemini_api_key');
    }
  }, [apiKey, rememberKey]);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3500);
  };

  const shouldIgnorePath = (path: string) => {
    const lower = path.toLowerCase();
    return IGNORED_PATH_SEGMENTS.some((segment) =>
      lower.includes(`/${segment}/`) ||
      lower.includes(`\\${segment}\\`) ||
      lower.startsWith(`${segment}/`),
    );
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    const newStagedFiles: StagedFile[] = [];
    const existingPaths = new Set(stagedFiles.map((file) => file.path));
    let runningTotal = totalSize;

    let skippedSensitive = 0;
    let skippedLarge = 0;
    let skippedIgnored = 0;
    let skippedDuplicate = 0;
    let skippedBinary = 0;
    let limitReached = false;

    for (let i = 0; i < files.length; i += 1) {
      const file = files[i];
      const relativePath = file.webkitRelativePath || file.name;

      if (shouldIgnorePath(relativePath)) {
        skippedIgnored += 1;
        continue;
      }

      if (!allowSensitiveFiles && SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(file.name))) {
        skippedSensitive += 1;
        continue;
      }

      if (existingPaths.has(relativePath)) {
        skippedDuplicate += 1;
        continue;
      }

      if (stagedFiles.length + newStagedFiles.length >= MAX_FILE_COUNT) {
        limitReached = true;
        break;
      }

      if (file.size > MAX_FILE_SIZE_BYTES) {
        skippedLarge += 1;
        continue;
      }

      if (runningTotal + file.size > MAX_TOTAL_SIZE_BYTES) {
        limitReached = true;
        break;
      }

      const text = await file.text();
      if (text.includes('\ufffd') || text.includes('\u0000')) {
        skippedBinary += 1;
        continue;
      }

      newStagedFiles.push({
        name: file.name,
        path: relativePath,
        content: text,
        size: file.size,
      });

      existingPaths.add(relativePath);
      runningTotal += file.size;
    }

    if (newStagedFiles.length > 0) {
      setStagedFiles((prev) => [...prev, ...newStagedFiles]);
      setResult(null);
      setAppliedFixes(new Set());
      setRedactionSummary(null);
    }

    const messages: string[] = [];
    if (skippedIgnored) messages.push(`Skipped ${skippedIgnored} ignored file${skippedIgnored > 1 ? 's' : ''}`);
    if (skippedSensitive) messages.push(`Skipped ${skippedSensitive} sensitive file${skippedSensitive > 1 ? 's' : ''}`);
    if (skippedLarge) messages.push(`Skipped ${skippedLarge} large file${skippedLarge > 1 ? 's' : ''}`);
    if (skippedDuplicate) messages.push(`Skipped ${skippedDuplicate} duplicate file${skippedDuplicate > 1 ? 's' : ''}`);
    if (skippedBinary) messages.push(`Skipped ${skippedBinary} binary-looking file${skippedBinary > 1 ? 's' : ''}`);
    if (limitReached) messages.push('File limit reached');
    if (messages.length > 0) showNotification(messages.join(' · '));

    if (event.target) event.target.value = '';
  };

  const removeFile = (path: string) => {
    setStagedFiles((prev) => prev.filter((file) => file.path !== path));
    setResult(null);
    setAppliedFixes(new Set());
    setRedactionSummary(null);
  };

  const handleAnalyze = async () => {
    if (stagedFiles.length === 0) return;
    if (!apiKey.trim()) {
      setError('Please provide a Gemini API key before running the audit.');
      return;
    }

    setLoading(true);
    setError(null);
    setAppliedFixes(new Set());

    const { files: redactedFiles, summary } = redactSecrets(stagedFiles);
    setRedactionSummary(summary);

    if (!redactEnabled && summary.totalMatches > 0 && !allowUnredactedSecrets) {
      setLoading(false);
      setError('Potential secrets detected. Enable redaction or allow unredacted sending to proceed.');
      return;
    }

    try {
      const filesToSend = redactEnabled ? redactedFiles : stagedFiles;
      const data = await securityAgent.analyzeFiles(filesToSend, apiKey);
      setResult(data);

      if (redactEnabled && summary.totalMatches > 0) {
        showNotification(
          `Redacted ${summary.totalMatches} secret-like string${summary.totalMatches > 1 ? 's' : ''} in ${summary.filesWithMatches} file${summary.filesWithMatches > 1 ? 's' : ''}`,
        );
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze files. Please check your API key.');
    } finally {
      setLoading(false);
    }
  };

  const handleSingleAutoFix = (vuln: Vulnerability) => {
    navigator.clipboard.writeText(vuln.fix);
    setAppliedFixes((prev) => {
      const next = new Set(prev);
      next.add(vuln.id);
      return next;
    });
    showNotification(`Patch for ${vuln.type} copied to clipboard!`);
  };

  const handleAutoFixAll = () => {
    if (!result) return;
    const prompt =
      `I need you to fix the following security vulnerabilities found in my project by Gemini Sentinel:\n\n` +
      result.vulnerabilities
        .map(
          (vuln) =>
            `[${vuln.severity}] in ${vuln.filePath} (${vuln.location})\n` +
            `Category: ${vuln.category}\n` +
            `Threat Model: ${vuln.threatModel}\n` +
            `Preconditions: ${vuln.preconditions}\n` +
            `Issue: ${vuln.description}\n` +
            `Suggested Fix:\n${vuln.fix}\n`,
        )
        .join('\n---\n\n') +
      `Please apply these fixes precisely to the relevant files.`;

    navigator.clipboard.writeText(prompt);

    const allIds = new Set(result.vulnerabilities.map((vuln) => vuln.id));
    setAppliedFixes(allIds);

    showNotification('All patches bundled and copied to clipboard for IDE injection!');
  };

  const severityCounts =
    result?.vulnerabilities.reduce((acc: Record<string, number>, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {}) || {};

  const chartData = [
    { name: 'Critical', value: severityCounts[Severity.CRITICAL] || 0, color: '#f87171' },
    { name: 'High', value: severityCounts[Severity.HIGH] || 0, color: '#fb923c' },
    { name: 'Medium', value: severityCounts[Severity.MEDIUM] || 0, color: '#facc15' },
    { name: 'Low', value: severityCounts[Severity.LOW] || 0, color: '#60a5fa' },
    { name: 'Needs Review', value: severityCounts[Severity.NEEDS_REVIEW] || 0, color: '#a78bfa' },
  ].filter((entry) => entry.value > 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 relative">
      {notification && (
        <div className="fixed top-24 right-5 z-50 animate-in fade-in slide-in-from-right-10 duration-300">
          <div className="bg-emerald-600 text-white px-6 py-4 rounded-xl shadow-2xl flex items-center space-x-3 border border-emerald-500">
            <div className="bg-white/20 p-1 rounded-full">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
            </div>
            <div>
              <p className="font-bold text-sm">Action Successful</p>
              <p className="text-xs text-emerald-100">{notification}</p>
            </div>
          </div>
        </div>
      )}

      <div className="lg:col-span-5 space-y-6">
        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.866-3.582 7-8 7m16 0c-4.418 0-8-3.134-8-7m8 0a8 8 0 10-16 0m16 0H4" />
              </svg>
              API Key & Privacy
            </h2>
            <span className="text-[10px] uppercase tracking-widest text-emerald-400 font-bold bg-emerald-500/10 px-2 py-1 rounded-full border border-emerald-500/20">
              Local Only
            </span>
          </div>

          <div className="mt-4">
            <label className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Gemini API Key</label>
            <div className="mt-2 flex items-center gap-2">
              <input
                type={showApiKey ? 'text' : 'password'}
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder="Paste your API key"
                className="flex-1 bg-slate-900/70 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
              <button
                onClick={() => setShowApiKey((prev) => !prev)}
                className="text-[10px] px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition-colors"
              >
                {showApiKey ? 'Hide' : 'Show'}
              </button>
              <button
                onClick={() => setApiKey('')}
                className="text-[10px] px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 transition-colors"
              >
                Clear
              </button>
            </div>

            <div className="mt-3 flex items-center gap-2">
              <input
                id="rememberKey"
                type="checkbox"
                checked={rememberKey}
                onChange={(event) => setRememberKey(event.target.checked)}
                className="h-3 w-3 rounded border-slate-600 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
              />
              <label htmlFor="rememberKey" className="text-xs text-slate-400">
                Remember for this session only
              </label>
            </div>
            <p className="text-[10px] text-slate-500 mt-2">
              The key is used only in your browser. It is not stored unless you opt in for this session.
            </p>
          </div>

          <div className="mt-4 border-t border-slate-700/60 pt-4">
            <p className="text-xs text-slate-300 font-semibold mb-2">Privacy Controls</p>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <input
                  id="redactSecrets"
                  type="checkbox"
                  checked={redactEnabled}
                  onChange={(event) => setRedactEnabled(event.target.checked)}
                  className="h-3 w-3 rounded border-slate-600 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
                />
                <label htmlFor="redactSecrets" className="text-xs text-slate-400">
                  Redact secret-like strings before analysis
                </label>
              </div>
              <div className="flex items-center gap-2">
                <input
                  id="allowSensitiveFiles"
                  type="checkbox"
                  checked={allowSensitiveFiles}
                  onChange={(event) => setAllowSensitiveFiles(event.target.checked)}
                  className="h-3 w-3 rounded border-slate-600 bg-slate-900 text-indigo-500 focus:ring-indigo-500"
                />
                <label htmlFor="allowSensitiveFiles" className="text-xs text-slate-400">
                  Allow sensitive files (.env, keys) to be staged
                </label>
              </div>
              <div className="flex items-center gap-2">
                <input
                  id="allowUnredacted"
                  type="checkbox"
                  checked={allowUnredactedSecrets}
                  onChange={(event) => setAllowUnredactedSecrets(event.target.checked)}
                  disabled={redactEnabled}
                  className="h-3 w-3 rounded border-slate-600 bg-slate-900 text-indigo-500 focus:ring-indigo-500 disabled:opacity-40"
                />
                <label htmlFor="allowUnredacted" className="text-xs text-slate-400">
                  Allow unredacted secrets to be sent (not recommended)
                </label>
              </div>
              {!redactEnabled && (
                <p className="text-[10px] text-amber-400">
                  Redaction is off. Enable it for safer analysis, or explicitly allow unredacted sending.
                </p>
              )}
            </div>

            {redactionSummary && redactionSummary.totalMatches > 0 && (
              <div className="mt-3 text-[10px] text-amber-300">
                Last scan redacted {redactionSummary.totalMatches} secret-like string{redactionSummary.totalMatches > 1 ? 's' : ''} across {redactionSummary.filesWithMatches} file{redactionSummary.filesWithMatches > 1 ? 's' : ''}.
              </div>
            )}
          </div>
        </div>
