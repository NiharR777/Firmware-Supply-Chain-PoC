
import React, { useState } from 'react';
import { X, Bot, Send, Sparkles, LoaderCircle } from 'lucide-react';

interface SpectraAdvisorModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ChatMessage {
  role: 'user' | 'assistant';
  text: string;
}

interface AdvisorResponse {
  answer?: string;
  detail?: string;
  provider?: string;
  model?: string;
  scenario_id?: string | null;
  advisory_only?: boolean;
  deployment_allowed?: boolean;
  real_action_executed?: boolean;
}

const INITIAL_GREETING =
  'Hello! I am SpectraIQ, your firmware supply-chain security advisor. Ask me about any of the 10 synthetic scenarios, SHA-256 integrity, digital signatures, vendor trust, SBOM vulnerabilities, VEX reachability, rollback attacks, or security recommendations.';

export const SpectraAdvisorModal: React.FC<SpectraAdvisorModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [query, setQuery] = useState('');
  const [history, setHistory] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleAsk = async (e: React.FormEvent) => {
    e.preventDefault();

    const userText = query.trim();

    if (!userText || loading) return;

    setQuery('');
    setError('');

    const previousHistory = history.slice(-10);

    const scenarioText = [
      ...previousHistory.map((message) => message.text),
      userText,
    ].join('\n');

    const scenarioMatch = scenarioText.match(
      /\bSC-(?:00[1-9]|010)\b/i
    );

    const scenarioId = scenarioMatch
      ? scenarioMatch[0].toUpperCase()
      : null;

    const updatedHistory: ChatMessage[] = [
      ...previousHistory,
      { role: 'user', text: userText },
    ];

    setHistory(updatedHistory);
    setLoading(true);

    try {
      const response = await fetch('/api/advisor/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: userText,
          scenario_id: scenarioId,
          history: previousHistory.slice(-10),
        }),
      });

      const data: AdvisorResponse = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || `Advisor request failed (HTTP ${response.status}).`
        );
      }

      if (!data.answer || typeof data.answer !== 'string') {
        throw new Error('The advisor returned an empty response.');
      }

      setHistory((current) => [
        ...current,
        {
          role: 'assistant',
          text: data.answer as string,
        },
      ]);
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Unable to connect to SpectraIQ Advisor.';

      setError(message);

      setHistory((current) => [
        ...current,
        {
          role: 'assistant',
          text: `I could not complete your request: ${message}\n\nPlease check that the FastAPI backend is running on port 8001 and try again.`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const suggestedQuestions = [
    {
      label: 'SC-001 Hash Integrity',
      question:
        'Explain the SHA-256 hash mismatch in SC-001. What is the security risk and what should be done?',
    },
    {
      label: 'SC-005 Rollback Risk',
      question:
        'Analyze SC-005 and explain the rollback attack, its evidence, and mitigation.',
    },
    {
      label: 'SC-004 VEX Analysis',
      question:
        'Explain the vulnerability and VEX reachability assessment in SC-004.',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-900 dark:text-slate-100 transition-colors">

        {/* Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
              <Bot className="w-5 h-5" />
            </div>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                SpectraIQ Supply-Chain &amp; MITRE Advisor
              </h3>

              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                AI-powered explanations based on deterministic evidence and
                synthetic firmware scenarios.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={loading}
            aria-label="Close advisor"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-40"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Conversation */}
        <div className="p-5 space-y-4 max-h-[60vh] min-h-[220px] overflow-y-auto">

          <div className="p-3.5 rounded-xl text-xs leading-relaxed whitespace-pre-wrap bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-800 mr-8">
            <div className="flex items-center gap-2 mb-2 text-emerald-600 dark:text-emerald-400 font-semibold">
              <Sparkles className="w-4 h-4" />
              SpectraIQ Advisor
            </div>
            {INITIAL_GREETING}
          </div>

          {history.map((msg, idx) => (
            <div
              key={idx}
              className={`p-3.5 rounded-xl text-xs leading-relaxed whitespace-pre-wrap break-words ${
                msg.role === 'user'
                  ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-950 dark:text-emerald-200 border border-emerald-200 dark:border-emerald-800/80 ml-8'
                  : 'bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-800 mr-8'
              }`}
            >
              {msg.text}
            </div>
          ))}

          {loading && (
            <div className="mr-8 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-300 flex items-center gap-2">
              <LoaderCircle className="w-4 h-4 animate-spin text-emerald-600" />
              SpectraIQ is analyzing the evidence with Gemini...
            </div>
          )}

          {error && (
            <div className="text-xs text-red-600 dark:text-red-400 px-2">
              Latest request error: {error}
            </div>
          )}
        </div>

        {/* Suggested Questions */}
        <div className="px-5 py-2 bg-slate-50 dark:bg-slate-950 border-t border-slate-100 dark:border-slate-800/60 flex flex-wrap gap-1.5 text-[11px]">
          {suggestedQuestions.map((item) => (
            <button
              key={item.label}
              type="button"
              disabled={loading}
              onClick={() => setQuery(item.question)}
              className="px-2.5 py-1 rounded-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-white transition-colors cursor-pointer disabled:opacity-40"
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Input */}
        <form
          onSubmit={handleAsk}
          className="p-4 bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2"
        >
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            disabled={loading}
            placeholder="Ask about SC-001, hash verification, rollback attacks, SBOM, or VEX..."
            className="flex-1 min-w-0 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:border-emerald-500 transition-colors disabled:opacity-50"
          />

          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors cursor-pointer flex items-center gap-1.5 shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <LoaderCircle className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Send className="w-3.5 h-3.5" />
            )}
            <span>{loading ? 'Analyzing' : 'Consult'}</span>
          </button>
        </form>

        {/* Safety Notice */}
        <div className="px-4 pb-3 text-center text-[10px] text-slate-400">
          AI advisory only · Human approval required · No firmware deployment
          or physical actions
        </div>
      </div>
    </div>
  );
};
