
import React, { useState, useCallback } from 'react';
import { securityAgent } from '../services/geminiService';
import { AnalysisResult, Severity } from '../types';
import VulnerabilityCard from './VulnerabilityCard';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const AgentDashboard: React.FC = () => {
  const [code, setCode] = useState<string>(`// Example vulnerable code snippet
function handleUserLogin(username, password) {
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.execute(query);
  
  // Store session in cookie without security flags
  document.cookie = "session_id=user123";
}

app.post('/api/profile', (req, res) => {
  const userId = req.body.userId;
  // Direct file access vulnerability
  const profile = fs.readFileSync(\`/data/profiles/\${userId}.json\`);
  res.send(profile);
});`);
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!code.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await securityAgent.analyzeCode(code);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze code. Please check your API key.');
    } finally {
      setLoading(false);
    }
  };

  const severityCounts = result?.vulnerabilities.reduce((acc: any, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {}) || {};

  const chartData = [
    { name: 'Critical', value: severityCounts[Severity.CRITICAL] || 0, color: '#f87171' },
    { name: 'High', value: severityCounts[Severity.HIGH] || 0, color: '#fb923c' },
    { name: 'Medium', value: severityCounts[Severity.MEDIUM] || 0, color: '#facc15' },
    { name: 'Low', value: severityCounts[Severity.LOW] || 0, color: '#60a5fa' },
  ].filter(d => d.value > 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
      {/* Left Column: Input */}
      <div className="lg:col-span-5 space-y-6">
        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              Code Input
            </h2>
            <div className="flex space-x-2">
              <span className="w-3 h-3 rounded-full bg-red-500/50"></span>
              <span className="w-3 h-3 rounded-full bg-yellow-500/50"></span>
              <span className="w-3 h-3 rounded-full bg-green-500/50"></span>
            </div>
          </div>
          
          <div className="relative group">
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="w-full h-[500px] bg-slate-950 text-slate-300 font-mono text-sm p-4 rounded-xl border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none transition-all resize-none"
              placeholder="Paste your source code here for security auditing..."
            />
            <div className="absolute top-2 right-2 flex space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
               <button className="p-1.5 bg-slate-800 rounded text-slate-400 hover:text-white" title="Clear Code" onClick={() => setCode('')}>
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
               </button>
            </div>
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading || !code.trim()}
            className={`w-full mt-6 py-3 px-6 rounded-xl font-bold flex items-center justify-center space-x-2 transition-all shadow-lg ${
              loading 
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed' 
                : 'bg-indigo-600 hover:bg-indigo-700 text-white shadow-indigo-600/20 active:scale-[0.98]'
            }`}
          >
            {loading ? (
              <>
                <svg className="animate-spin h-5 w-5 mr-3 text-white" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>Agent Reasoning...</span>
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
                </svg>
                <span>Audit for Vulnerabilities</span>
              </>
            )}
          </button>
          
          {error && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
              <div className="flex items-center mb-1">
                 <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                 </svg>
                 <span className="font-bold">Analysis Failed</span>
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
              What is OpenClaw?
           </h3>
           <p className="text-sm text-slate-400 leading-relaxed">
             OpenClaw refers to the shift towards <strong>Autonomous Software Security Agents</strong>. Using Gemini's reasoning capabilities, these agents autonomously scan repositories, identify zero-days, and generate PRs for security fixes without human intervention.
           </p>
           <div className="mt-4 flex items-center space-x-2 text-xs font-medium text-slate-500 italic">
             <span>Inspired by @iruletheworldmo</span>
             <span className="h-1 w-1 bg-slate-600 rounded-full"></span>
             <span>Gemini 3 Pro</span>
           </div>
        </div>
      </div>

      {/* Right Column: Results */}
      <div className="lg:col-span-7 space-y-6">
        {!result && !loading && !error && (
          <div className="h-full min-h-[400px] flex flex-col items-center justify-center bg-slate-900/40 border-2 border-dashed border-slate-800 rounded-3xl p-12 text-center">
            <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mb-6">
               <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                 <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
               </svg>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Ready for Analysis</h3>
            <p className="text-slate-500 max-w-md">
              Deploy the Gemini Sentinel agent to perform a deep security audit on your source code.
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
            {/* Summary Banner */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 mb-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex-1">
                  <h2 className="text-2xl font-bold text-white mb-2">Audit Report</h2>
                  <p className="text-slate-400 text-sm leading-relaxed mb-4">{result.summary}</p>
                  <div className="flex flex-wrap gap-3">
                    {chartData.map((d) => (
                      <div key={d.name} className="flex items-center space-x-2 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-700">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                        <span className="text-xs font-bold text-slate-300">{d.value} {d.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="w-full md:w-48 h-48 flex flex-col items-center justify-center relative">
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
                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }}
                        itemStyle={{ color: '#fff' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-3xl font-black text-white">{result.riskScore}</span>
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">Risk Score</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Vulnerability List */}
            <div className="space-y-4">
              <h3 className="text-sm font-bold text-slate-500 uppercase tracking-widest px-1">Detected Flaws ({result.vulnerabilities.length})</h3>
              {result.vulnerabilities.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
              ))}
            </div>
            
            {result.vulnerabilities.length === 0 && (
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-2xl p-12 text-center">
                <div className="w-16 h-16 bg-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-emerald-400 mb-2">Code Secure</h3>
                <p className="text-slate-400">Gemini Sentinel found no vulnerabilities in the provided snippet.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentDashboard;
