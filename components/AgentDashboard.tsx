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
  const [proxyStatus, setProxyStatus] = useState<'checking' | 'ready' | 'missing-key' | 'offline'>('checking');
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
    let cancelled = false;

    const checkProxy = async () => {
      try {
        const response = await fetch('/api/health');
        if (!response.ok) throw new Error('Proxy unavailable');
        const data = await response.json();
        if (cancelled) return;
        if (data?.status === 'ok') {
          setProxyStatus(data.hasKey ? 'ready' : 'missing-key');
        } else {
          setProxyStatus('offline');
        }
      } catch {
        if (!cancelled) setProxyStatus('offline');
      }
    };

    checkProxy();
    return () => {
      cancelled = true;
    };
  }, []);

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
    if (messages.length > 0) showNotification(messages.join(' | '));

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
    if (proxyStatus === 'missing-key') {
      setError('Server proxy is missing GEMINI_API_KEY. Set it in the server environment.');
      return;
    }
    if (proxyStatus === 'offline') {
      setError('Proxy server is offline. Start the server and try again.');
      return;
    }
    if (proxyStatus === 'checking') {
      setError('Checking proxy status. Please retry in a moment.');
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
      const data = await securityAgent.analyzeFiles(filesToSend);
      setResult(data);

      if (redactEnabled && summary.totalMatches > 0) {
        showNotification(
          `Redacted ${summary.totalMatches} secret-like string${summary.totalMatches > 1 ? 's' : ''} in ${summary.filesWithMatches} file${summary.filesWithMatches > 1 ? 's' : ''}`,
        );
      }
    } catch (err: any) {
      setError(err.message || 'Failed to analyze files. Please check the proxy server.');
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

  const proxyBadge = {
    checking: { label: 'Checking', className: 'bg-slate-700/40 text-slate-300 border-slate-600/40' },
    ready: { label: 'Ready', className: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
    'missing-key': { label: 'Missing Key', className: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
    offline: { label: 'Offline', className: 'bg-red-500/10 text-red-400 border-red-500/20' },
  }[proxyStatus];

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
              Proxy Status & Privacy
            </h2>
            <span className="text-[10px] uppercase tracking-widest text-indigo-300 font-bold bg-indigo-500/10 px-2 py-1 rounded-full border border-indigo-500/20">
              Server Proxy
            </span>
          </div>

          <div className="mt-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Proxy Status</span>
              <span className={`text-[10px] uppercase tracking-widest font-bold px-2 py-1 rounded-full border ${proxyBadge.className}`}>
                {proxyBadge.label}
              </span>
            </div>
            <div className="text-xs text-slate-400 space-y-1">
              <p>Requests are sent to the local proxy at <span className="font-mono text-slate-300">/api/analyze</span>.</p>
              <p>Set <span className="font-mono text-slate-300">GEMINI_API_KEY</span> in the server environment to enable audits.</p>
            </div>
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

        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
              </svg>
              Staged Source Code
            </h2>
            <div className="flex space-x-2">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                multiple
                className="hidden"
              />
              <input
                type="file"
                ref={folderInputRef}
                onChange={handleFileUpload}
                // @ts-ignore
                webkitdirectory=""
                directory=""
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="text-xs px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-200 transition-colors"
              >
                + Files
              </button>
              <button
                onClick={() => folderInputRef.current?.click()}
                className="text-xs px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 rounded-lg border border-indigo-500/20 transition-colors"
              >
                + Folder
              </button>
            </div>
          </div>

          <div className="bg-slate-950 rounded-xl border border-slate-800 h-[400px] overflow-y-auto custom-scrollbar">
            {stagedFiles.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center p-8 text-center">
                <div className="w-12 h-12 bg-slate-900 rounded-lg flex items-center justify-center mb-4 text-slate-700">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                <p className="text-sm text-slate-500">No files staged for analysis</p>
                <p className="text-[10px] text-slate-600 mt-2 uppercase tracking-widest font-bold">Upload project folder to begin</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800">
                {stagedFiles.map((file) => (
                  <div
                    key={file.path}
                    className="flex items-center justify-between p-3 hover:bg-slate-900/50 transition-colors group"
                  >
                    <div className="flex items-center space-x-3 overflow-hidden">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-slate-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <div className="flex flex-col overflow-hidden">
                        <span className="text-xs font-mono text-slate-300 truncate" title={file.path}>
                          {file.name}
                        </span>
                        <span className="text-[10px] text-slate-600 font-mono truncate">
                          {file.path}
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => removeFile(file.path)}
                      className="p-1.5 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 flex items-center justify-between px-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">
              {stagedFiles.length} {stagedFiles.length === 1 ? 'File' : 'Files'} Staged | {formatBytes(totalSize)} total
            </span>
            {stagedFiles.length > 0 && (
              <button
                onClick={() => {
                  setStagedFiles([]);
                  setResult(null);
                  setAppliedFixes(new Set());
                  setRedactionSummary(null);
                }}
                className="text-[10px] text-red-500/70 hover:text-red-500 font-bold uppercase tracking-widest transition-colors"
              >
                Clear All
              </button>
            )}
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading || stagedFiles.length === 0 || proxyStatus !== 'ready'}
            className={`w-full mt-6 py-4 px-6 rounded-xl font-bold flex items-center justify-center space-x-2 transition-all shadow-lg ${
              loading
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : stagedFiles.length === 0 || proxyStatus !== 'ready'
                  ? 'bg-slate-800 text-slate-600 border border-slate-700'
                  : 'bg-indigo-600 hover:bg-indigo-700 text-white shadow-indigo-600/20 active:scale-[0.98]'
            }`}
          >
            {loading ? (
              <>
                <svg className="animate-spin h-5 w-5 mr-3 text-white" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>Sentinel Reasoning...</span>
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 19.444a11.954 11.954 0 007.834-14.445 11.954 11.954 0 00-15.668 0z" />
                </svg>
                <span>Initiate Security Audit</span>
              </>
            )}
          </button>

          {proxyStatus !== 'ready' && (
            <p className="text-[10px] text-amber-400 mt-2">
              Proxy not ready. Ensure the server is running with GEMINI_API_KEY set.
            </p>
          )}

          {error && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              <div className="flex items-center mb-1">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="font-bold">Agent Offline</span>
              </div>
              {error}
            </div>
          )}
        </div>

        <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6">
          <h3 className="text-slate-200 font-semibold mb-3 flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            OpenClaw Autonomous Agents
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            OpenClaw refers to the paradigm shift where <strong>AI Agents</strong> act as the primary maintainers of code security. Sentinel uses Gemini 3 Pro&apos;s huge context and reasoning budget to find deep logical flaws that traditional static analysis tools miss.
          </p>
        </div>
      </div>

      <div className="lg:col-span-7 space-y-6">
        {!result && !loading && !error && (
          <div className="h-full min-h-[400px] flex flex-col items-center justify-center bg-slate-900/40 border-2 border-dashed border-slate-800 rounded-3xl p-12 text-center">
            <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mb-6">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Sentinel Deployment</h3>
            <p className="text-slate-500 max-w-md">
              Stage individual files or a project folder for a complete security landscape analysis.
            </p>
          </div>
        )}

        {loading && (
          <div className="space-y-4 animate-pulse">
            <div className="h-64 bg-slate-800/50 rounded-2xl"></div>
            <div className="h-32 bg-slate-800/50 rounded-2xl"></div>
            <div className="h-32 bg-slate-800/50 rounded-2xl"></div>
          </div>
        )}

        {result && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-700">
            <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 mb-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <h2 className="text-2xl font-bold text-white">Full Project Report</h2>
                    <span className="bg-indigo-600/20 text-indigo-400 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border border-indigo-500/20">
                      Verified Audit
                    </span>
                  </div>
                  <p className="text-slate-400 text-sm leading-relaxed mb-6">{result.summary}</p>

                  <div className="flex flex-wrap gap-2 mb-6">
                    {chartData.map((entry) => (
                      <div key={entry.name} className="flex items-center space-x-2 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></span>
                        <span className="text-xs font-bold text-slate-300">
                          {entry.value} {entry.name}
                        </span>
                      </div>
                    ))}
                  </div>

                  {result.vulnerabilities.length > 0 && (
                    <button
                      onClick={handleAutoFixAll}
                      className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold px-4 py-3 rounded-lg transition-all shadow-lg shadow-emerald-600/20 hover:shadow-emerald-600/30 active:scale-95 border border-emerald-500"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                      </svg>
                      <span>Auto-Fix All Issues (Copy Agent Prompt)</span>
                    </button>
                  )}
                </div>

                <div className="w-full md:w-48 h-48 flex flex-col items-center justify-center relative bg-slate-900/50 rounded-2xl border border-slate-800">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={chartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={70}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          border: '1px solid #334155',
                          borderRadius: '8px',
                        }}
                        itemStyle={{ color: '#fff' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-3xl font-black text-white">{result.riskScore}</span>
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Project Risk</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-500 uppercase tracking-widest px-1">
                  Active Vulnerabilities ({result.vulnerabilities.length})
                </h3>
                {appliedFixes.size > 0 && (
                  <span className="text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded-full border border-emerald-500/20">
                    {appliedFixes.size} / {result.vulnerabilities.length} Resolved
                  </span>
                )}
              </div>

              {result.vulnerabilities
                .sort((a, b) => {
                  const order = {
                    [Severity.CRITICAL]: 0,
                    [Severity.HIGH]: 1,
                    [Severity.MEDIUM]: 2,
                    [Severity.LOW]: 3,
                    [Severity.NEEDS_REVIEW]: 4,
                  };
                  return order[a.severity] - order[b.severity];
                })
                .map((vuln) => (
                  <VulnerabilityCard
                    key={vuln.id}
                    vulnerability={vuln}
                    isFixed={appliedFixes.has(vuln.id)}
                    onAutoFix={() => handleSingleAutoFix(vuln)}
                  />
                ))}
            </div>

            {result.vulnerabilities.length === 0 && (
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-2xl p-12 text-center">
                <div className="w-16 h-16 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-emerald-400 mb-2">Secure Foundation</h3>
                <p className="text-slate-400">Gemini Sentinel has verified the codebase. No security flaws were detected.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentDashboard;

