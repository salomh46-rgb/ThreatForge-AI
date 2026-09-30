import { useState, useEffect } from 'react';
import { X, Award, CheckCircle2, AlertTriangle, XCircle, Shield } from 'lucide-react';

interface ComplianceModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentCode: string;
}

export const ComplianceModal: React.FC<ComplianceModalProps> = ({ isOpen, onClose, currentCode }) => {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>(null);

  useEffect(() => {
    if (isOpen && currentCode) {
      loadAudit();
    }
  }, [isOpen, currentCode]);

  const loadAudit = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/compliance/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_code: currentCode, format: 'auto' })
      });
      const data = await res.json();
      setReport(data);
    } catch (err) {
      console.error('Failed to load compliance audit:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLIANT':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
            <CheckCircle2 className="w-3.5 h-3.5" /> Compliant
          </span>
        );
      case 'WARNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5" /> Warning
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">
            <XCircle className="w-3.5 h-3.5" /> Non-Compliant
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-950 border border-emerald-700 text-emerald-400">
              <Award className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                Enterprise Regulatory & Compliance Audit Matrix
              </h3>
              <p className="text-xs text-slate-400 m-0">
                Automated Mapping to PCI-DSS v4.0, ISO 27001:2022, SOC 2 Type II & O'zbekiston KHM
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
          {loading ? (
            <div className="p-12 text-center text-slate-400 text-xs font-mono">
              Evaluating architectural controls against international standards...
            </div>
          ) : report ? (
            <>
              {/* Overall Scorecard */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    Overall Compliance Status
                  </div>
                  <div className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-emerald-400" />
                    {report.summary_verdict}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-black font-mono text-emerald-400">
                    {report.overall_compliance}%
                  </div>
                  <div className="text-[10px] text-slate-400">Average Readiness Score</div>
                </div>
              </div>

              {/* 4 Framework Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.values(report.frameworks).map((fw: any) => (
                  <div
                    key={fw.framework_id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="text-xs font-bold text-slate-100">{fw.framework_name}</h4>
                        <span className="text-[10px] text-slate-500">{fw.category}</span>
                      </div>
                      {getStatusBadge(fw.status)}
                    </div>

                    {/* Progress Bar */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px] font-mono text-slate-400">
                        <span>Readiness:</span>
                        <span className="font-bold text-slate-200">{fw.compliance_percentage}%</span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            fw.compliance_percentage >= 90
                              ? 'bg-emerald-500'
                              : fw.compliance_percentage >= 70
                              ? 'bg-amber-500'
                              : 'bg-red-500'
                          }`}
                          style={{ width: `${fw.compliance_percentage}%` }}
                        />
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Passing {fw.passing_controls} of {fw.total_controls} standard controls
                      </div>
                    </div>

                    {/* Violations List */}
                    {fw.violations.length > 0 && (
                      <div className="pt-2 border-t border-slate-800/80 space-y-2">
                        <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">
                          Failed Controls ({fw.violations.length}):
                        </span>
                        <div className="space-y-1 max-h-28 overflow-y-auto pr-1">
                          {fw.violations.map((v: any, idx: number) => (
                            <div
                              key={idx}
                              className="p-1.5 rounded bg-red-950/20 border border-red-900/30 text-[10px] text-slate-300 space-y-0.5"
                            >
                              <div className="font-semibold text-red-300 truncate">{v.control_name}</div>
                              <div className="text-slate-400 leading-tight line-clamp-1">{v.description}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-slate-500 text-xs">
              No architecture loaded to audit.
            </div>
          )}
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
