import { useState, useEffect } from 'react';
import { X, ShieldAlert, Trash2, Clock, UserCheck } from 'lucide-react';
import type { ThreatFinding } from '../types';

interface RiskAcceptModalProps {
  isOpen: boolean;
  onClose: () => void;
  threat: ThreatFinding | null;
}

export const RiskAcceptModal: React.FC<RiskAcceptModalProps> = ({ isOpen, onClose, threat }) => {
  const [justification, setJustification] = useState('');
  const [approvedBy, setApprovedBy] = useState('Javohirbek Asqarov (CISO)');
  const [daysValid, setDaysValid] = useState(90);
  const [exceptions, setExceptions] = useState<any[]>([]);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadExceptions();
    }
  }, [isOpen]);

  const loadExceptions = async () => {
    try {
      const res = await fetch('/api/integrations/risk/exceptions');
      const data = await res.json();
      setExceptions(data);
    } catch (err) {
      console.error(err);
    }
  };

  if (!isOpen) return null;

  const handleAccept = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!threat || !justification.trim()) return;

    setSubmitting(true);
    try {
      const res = await fetch('/api/integrations/risk/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_id: threat.id,
          threat_title: threat.title,
          target_node: threat.target_name,
          justification,
          approved_by: approvedBy,
          days_valid: daysValid
        })
      });

      if (res.ok) {
        setJustification('');
        loadExceptions();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await fetch(`/api/integrations/risk/exceptions/${id}`, { method: 'DELETE' });
      loadExceptions();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-950 border border-amber-700 text-amber-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                Enterprise Risk Acceptance & Exception Management
              </h3>
              <p className="text-xs text-slate-400 m-0">
                Formal Sign-Off and Audit Trail for Accepted Architectural Vulnerabilities
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
          {threat ? (
            /* Acceptance Form */
            <form onSubmit={handleAccept} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                    {threat.severity}
                  </span>
                  <span className="text-xs font-bold text-slate-200">{threat.title}</span>
                </div>
                <div className="text-[11px] text-slate-400">Target Node: `{threat.target_name}`</div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Business & Technical Justification (Required for Audit):
                </label>
                <textarea
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  placeholder="e.g., Isolated staging cluster with synthetic test data; compensating controls implemented via private VPN link."
                  className="w-full h-20 p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-amber-500 resize-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <label className="block font-semibold text-slate-300 mb-1">Approved By (CISO / Architect):</label>
                  <input
                    type="text"
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                    required
                  />
                </div>
                <div>
                  <label className="block font-semibold text-slate-300 mb-1">Validity Period:</label>
                  <select
                    value={daysValid}
                    onChange={(e) => setDaysValid(Number(e.target.value))}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                  >
                    <option value={30}>30 Days (Short-term grace)</option>
                    <option value={60}>60 Days</option>
                    <option value={90}>90 Days (Standard quarter)</option>
                    <option value={180}>180 Days (Half-year)</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={submitting || !justification.trim()}
                  className="px-4 py-2 rounded-lg text-xs font-bold bg-amber-600 hover:bg-amber-500 disabled:bg-slate-800 text-white flex items-center gap-1.5 transition-all shadow-md"
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  Electronically Sign & Accept Risk
                </button>
              </div>
            </form>
          ) : (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
              Select a specific threat in the Threat Matrix to sign off a risk exception.
            </div>
          )}

          {/* Active Exceptions Log */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Active Risk Exceptions & Audit Registry ({exceptions.length})
            </h4>

            {exceptions.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs font-mono">
                No active risk exceptions recorded.
              </div>
            ) : (
              <div className="space-y-2">
                {exceptions.map((exc) => (
                  <div
                    key={exc.id}
                    className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-100">{exc.threat_title}</span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                            exc.status === 'ACTIVE'
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-slate-800 text-slate-500'
                          }`}
                        >
                          {exc.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-snug">{exc.justification}</p>
                      <div className="text-[10px] text-slate-500 font-mono">
                        Approved by: <strong className="text-slate-300">{exc.approved_by}</strong> · Expires: {exc.expires_at}
                      </div>
                    </div>

                    {exc.status === 'ACTIVE' && (
                      <button
                        onClick={() => handleRevoke(exc.id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-900 transition-colors"
                        title="Revoke Exception"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
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
