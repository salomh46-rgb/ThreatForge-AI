import React, { useState } from 'react';
import { X, GitPullRequest, Copy, Check, Terminal, Play, ShieldAlert, ShieldCheck } from 'lucide-react';

interface CIGateModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentCode: string;
}

export const CIGateModal: React.FC<CIGateModalProps> = ({ isOpen, onClose, currentCode }) => {
  const [copiedAction, setCopiedAction] = useState(false);
  const [copiedCli, setCopiedCli] = useState(false);
  const [testingGate, setTestingGate] = useState(false);
  const [gateResult, setGateResult] = useState<any>(null);

  if (!isOpen) return null;

  const githubActionYaml = `name: "ThreatForge Architecture Gate"
on: [pull_request, push]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r backend/requirements.txt
      - name: Evaluate ThreatForge Security Gate
        run: |
          PYTHONPATH=backend python -m app.cli scan docker-compose.yml \\
            --fail-on CRITICAL \\
            --min-score 70 \\
            --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif`;

  const cliSnippet = `python -m app.cli scan docker-compose.yml --fail-on CRITICAL --min-score 70 --sarif results.sarif`;

  const copyToClipboard = (text: string, type: 'action' | 'cli') => {
    navigator.clipboard.writeText(text);
    if (type === 'action') {
      setCopiedAction(true);
      setTimeout(() => setCopiedAction(false), 2000);
    } else {
      setCopiedCli(true);
      setTimeout(() => setCopiedCli(false), 2000);
    }
  };

  const handleTestGate = async () => {
    setTestingGate(true);
    try {
      const res = await fetch('/api/ci/gate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_code: currentCode,
          format: 'auto',
          fail_on: 'CRITICAL',
          min_score: 70
        })
      });
      const data = await res.json();
      setGateResult(data);
    } catch (err: any) {
      alert(`CI Gate test failed: ${err.message}`);
    } finally {
      setTestingGate(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-950 border border-indigo-700 text-indigo-400">
              <GitPullRequest className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                Enterprise CI/CD Security Gate & GitHub Actions Bot
              </h3>
              <p className="text-xs text-slate-400 m-0">
                Automated Quality Gate, SARIF Upload, and PR Bot Integration
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Interactive Test CI Gate */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                  <Play className="w-3.5 h-3.5 text-cyan-400" />
                  Live CI/CD Gate Simulator
                </h4>
                <p className="text-[11px] text-slate-400">
                  Simulate how GitHub Actions evaluates the current architecture before PR merge.
                </p>
              </div>
              <button
                onClick={handleTestGate}
                disabled={testingGate}
                className="px-3 py-1.5 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white flex items-center gap-1.5 shadow-sm transition-all"
              >
                {testingGate ? 'Evaluating...' : 'Run CI Gate Check'}
              </button>
            </div>

            {gateResult && (
              <div
                className={`p-3 rounded-lg border text-xs space-y-2 ${
                  gateResult.passed
                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                    : 'bg-red-950/30 border-red-500/40 text-red-300'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span className="flex items-center gap-2">
                    {gateResult.passed ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-red-400" />
                    )}
                    {gateResult.verdict}
                  </span>
                  <span>Score: {gateResult.security_score}/100</span>
                </div>
                <div className="text-[11px] font-mono text-slate-300">
                  Violations: {gateResult.blocking_violations?.length || 0} blocking | Critical: {gateResult.critical_count} | High: {gateResult.high_count}
                </div>
              </div>
            )}
          </div>

          {/* GitHub Action Snippet */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <GitPullRequest className="w-4 h-4 text-cyan-400" />
                GitHub Actions Workflow (<code>.github/workflows/threatforge.yml</code>)
              </span>
              <button
                onClick={() => copyToClipboard(githubActionYaml, 'action')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1 transition-all"
              >
                {copiedAction ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedAction ? 'Copied!' : 'Copy YAML'}
              </button>
            </div>
            <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre leading-relaxed">
              <code>{githubActionYaml}</code>
            </pre>
          </div>

          {/* CLI Scanner Snippet */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Terminal / CI Runner Command
              </span>
              <button
                onClick={() => copyToClipboard(cliSnippet, 'cli')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono flex items-center gap-1 transition-all"
              >
                {copiedCli ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedCli ? 'Copied!' : 'Copy Command'}
              </button>
            </div>
            <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre">
              <code>{cliSnippet}</code>
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
