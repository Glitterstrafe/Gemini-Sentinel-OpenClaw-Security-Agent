
import React from 'react';
import Header from './components/Header';
import AgentDashboard from './components/AgentDashboard';

const App: React.FC = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      
      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full">
        <div className="mb-10 text-center lg:text-left">
          <h2 className="text-3xl sm:text-4xl font-black text-white mb-4 tracking-tight">
            Autonomous Security <span className="text-indigo-500">Intelligence</span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl leading-relaxed">
            The next generation of vulnerability management. Gemini-powered agents for identifying, explaining, and patching complex security flaws in real-time.
          </p>
        </div>

        <AgentDashboard />
      </main>

      <footer className="border-t border-slate-800 bg-slate-900/30 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-sm text-slate-500">
              &copy; {new Date().getFullYear()} Gemini Sentinel Node. Part of the OpenClaw Security Initiative.
            </p>
            <div className="flex space-x-6 text-sm font-medium text-slate-400">
              <a href="#" className="hover:text-white transition-colors">Documentation</a>
              <a href="#" className="hover:text-white transition-colors">Github</a>
              <a href="#" className="hover:text-white transition-colors">API Keys</a>
            </div>
          </div>
        </div>
      </footer>

      {/* Background Decor */}
      <div className="fixed top-0 left-0 w-full h-full -z-10 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-600/10 blur-[120px] rounded-full"></div>
        <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-blue-600/10 blur-[100px] rounded-full"></div>
      </div>
    </div>
  );
};

export default App;
