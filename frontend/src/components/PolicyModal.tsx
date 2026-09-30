import { useState, useEffect } from 'react';
import { X, Sliders, Plus, Trash2 } from 'lucide-react';

interface PolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const PolicyModal: React.FC<PolicyModalProps> = ({ isOpen, onClose }) => {
  const [policies, setPolicies] = useState<any[]>([]);
  const [isAdding, setIsAdding] = useState(false);

  // New Policy Form State
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetType, setTargetType] = useState('database');
  const [condition, setCondition] = useState('NO_PUBLIC_ACCESS');
  const [severity, setSeverity] = useState('HIGH');
  const [remediation, setRemediation] = useState('');

  useEffect(() => {
    if (isOpen) {
      loadPolicies();
    }
  }, [isOpen]);

  const loadPolicies = async () => {
    try {
      const res = await fetch('/api/policies');
      const data = await res.json();
      setPolicies(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          description,
          target_type: targetType,
          target_zone: 'ALL',
          rule_condition: condition,
          severity,
          remediation_advice: remediation,
          is_enabled: true
        })
      });

      if (res.ok) {
        setName('');
        setDescription('');
        setRemediation('');
        setIsAdding(false);
        loadPolicies();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/policies/${id}`, { method: 'DELETE' });
      loadPolicies();
    } catch (err) {
      console.error(err);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-950 border border-purple-700 text-purple-400">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 m-0">
                Custom Enterprise Security Policy Engine (OPA/Rego)
              </h3>
              <p className="text-xs text-slate-400 m-0">
                Enforce Custom Organizational Security Invariants & Compliance Rules
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
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              Active Corporate Invariant Rules ({policies.length})
            </span>
            <button
              onClick={() => setIsAdding(!isAdding)}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white flex items-center gap-1.5 shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              {isAdding ? 'Cancel' : 'New Custom Policy'}
            </button>
          </div>

          {/* Add Form */}
          {isAdding && (
            <form onSubmit={handleCreate} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 text-xs">
              <h4 className="font-bold text-slate-200">Define Organization Invariant Rule:</h4>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Policy Rule Name & Code:</label>
                <input
                  type="text"
                  placeholder="e.g. CORP-SEC-04: Mandatory KMS Encryption on All Databases"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Target Component:</label>
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  >
                    <option value="database">Database</option>
                    <option value="cache">Cache (Redis)</option>
                    <option value="storage_bucket">Storage Bucket (S3)</option>
                    <option value="load_balancer">Load Balancer</option>
                    <option value="ALL">All Components</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Rule Invariant:</label>
                  <select
                    value={condition}
                    onChange={(e) => setCondition(e.target.value)}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  >
                    <option value="NO_PUBLIC_ACCESS">Prohibit Public Internet Access</option>
                    <option value="FORBID_PLAIN_HTTP">Forbid Unencrypted Plaintext HTTP</option>
                    <option value="REQUIRE_WAF">Require Ingress WAF Protection</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Severity:</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Remediation Guidance:</label>
                <input
                  type="text"
                  placeholder="e.g. Bind DB instance strictly to private VPC subnet 10.0.2.0/24"
                  value={remediation}
                  onChange={(e) => setRemediation(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg font-bold bg-purple-600 hover:bg-purple-500 text-white transition-all shadow-md"
                >
                  Save & Enforce Policy
                </button>
              </div>
            </form>
          )}

          {/* List Policies */}
          <div className="space-y-3">
            {policies.map((p) => (
              <div
                key={p.id}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 flex items-start justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-100">{p.name}</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      {p.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{p.description}</p>
                  <div className="text-[10px] text-slate-500 font-mono">
                    Target: {p.target_type} · Condition: {p.rule_condition}
                  </div>
                </div>

                <button
                  onClick={() => handleDelete(p.id)}
                  className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-900 transition-colors"
                  title="Remove Rule"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
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
