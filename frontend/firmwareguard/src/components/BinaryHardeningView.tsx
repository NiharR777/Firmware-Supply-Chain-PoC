import React, { useState } from 'react';
import { FirmwareAsset, ExposedSecret } from '../types/firmware';
import {
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  FileCode,
  Terminal,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  Search
} from 'lucide-react';

interface BinaryHardeningViewProps {
  assets: FirmwareAsset[];
}

export const BinaryHardeningView: React.FC<BinaryHardeningViewProps> = ({ assets }) => {
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');
  const [selectedSecret, setSelectedSecret] = useState<ExposedSecret | null>(
    assets[0]?.secrets[0] || null
  );

  const currentAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const allSecrets: { asset: FirmwareAsset; secret: ExposedSecret }[] = [];
  assets.forEach((a) => {
    a.secrets.forEach((s) => allSecrets.push({ asset: a, secret: s }));
  });

  return (
    <div className="space-y-6">
      {/* Header and Asset Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
            FIRMWARE BINARY ANALYSIS
          </div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5 flex items-center gap-2">
            <Lock className="w-5 h-5 text-emerald-600 dark:text-cyan-400" />
            <span>Firmware Hardening &amp; Cryptographic Exposure Analyzer</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Compiler mitigation flags (NX/ASLR/Canaries) and embedded flash secrets (private keys, tokens, debug shells).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-slate-600 dark:text-slate-400 font-medium">Target Device:</label>
          <select
            value={currentAsset?.id}
            onChange={(e) => {
              setSelectedAssetId(e.target.value);
              const found = assets.find((a) => a.id === e.target.value);
              if (found && found.secrets.length > 0) {
                setSelectedSecret(found.secrets[0]);
              } else {
                setSelectedSecret(null);
              }
            }}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-900 dark:text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.model})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Compiler Mitigations Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs uppercase tracking-wider font-bold text-slate-700 dark:text-slate-300">
            Binary Protection Flags for {currentAsset.name} ({currentAsset.architecture})
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            OS: {currentAsset.osType}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* NX / DEP */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">NX / DEP</span>
              {currentAsset.hardening.nxDep ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-600" />
              )}
            </div>
            <div className="text-[11px] text-slate-500">
              Stack Execution
            </div>
            <span
              className={`text-[10px] font-mono mt-2 font-bold ${
                currentAsset.hardening.nxDep ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-700 dark:text-rose-400'
              }`}
            >
              {currentAsset.hardening.nxDep ? 'ENABLED' : 'DISABLED'}
            </span>
          </div>

          {/* ASLR / PIE */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">ASLR / PIE</span>
              {currentAsset.hardening.aslrPie ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-500" />
              )}
            </div>
            <div className="text-[11px] text-slate-500">
              Address Space Layout
            </div>
            <span
              className={`text-[10px] font-mono mt-2 font-bold ${
                currentAsset.hardening.aslrPie ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'
              }`}
            >
              {currentAsset.hardening.aslrPie ? 'ENABLED' : 'N/A (RTOS)'}
            </span>
          </div>

          {/* Stack Canaries */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">Stack Canaries</span>
              {currentAsset.hardening.stackCanary ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-600" />
              )}
            </div>
            <div className="text-[11px] text-slate-500">
              Smashing Guard
            </div>
            <span
              className={`text-[10px] font-mono mt-2 font-bold ${
                currentAsset.hardening.stackCanary ? 'text-emerald-700 dark:text-emerald-400' : 'text-rose-700 dark:text-rose-400'
              }`}
            >
              {currentAsset.hardening.stackCanary ? 'PRESENT' : 'ABSENT'}
            </span>
          </div>

          {/* RELRO */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">RELRO</span>
              <span className="text-[10px] font-mono font-bold text-slate-700 dark:text-slate-300">{currentAsset.hardening.relro}</span>
            </div>
            <div className="text-[11px] text-slate-500">
              Read-Only Relocations
            </div>
            <span className="text-[10px] font-mono mt-2 font-bold text-slate-700 dark:text-slate-300">
              {currentAsset.hardening.relro} RELRO
            </span>
          </div>

          {/* Fortify Source */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">Fortify Source</span>
              {currentAsset.hardening.fortifySource ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <XCircle className="w-4 h-4 text-slate-400" />
              )}
            </div>
            <div className="text-[11px] text-slate-500">
              _FORTIFY_SOURCE
            </div>
            <span
              className={`text-[10px] font-mono mt-2 font-bold ${
                currentAsset.hardening.fortifySource ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500'
              }`}
            >
              {currentAsset.hardening.fortifySource ? 'ACTIVE' : 'INACTIVE'}
            </span>
          </div>

          {/* Stripped Symbols */}
          <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-slate-800 dark:text-slate-200">Symbols</span>
              {currentAsset.hardening.strippedSymbols ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-500" />
              )}
            </div>
            <div className="text-[11px] text-slate-500">
              Symbol Stripping
            </div>
            <span
              className={`text-[10px] font-mono mt-2 font-bold ${
                currentAsset.hardening.strippedSymbols ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'
              }`}
            >
              {currentAsset.hardening.strippedSymbols ? 'STRIPPED' : 'UNSTRIPPED (DEBUG)'}
            </span>
          </div>
        </div>
      </div>

      {/* Cryptographic Secrets & Insecure Interfaces Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: List of Detected Secrets across assets (6 Cols) */}
        <div className="lg:col-span-6 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-700 dark:text-slate-300 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-rose-500" />
              <span>Extracted Secrets &amp; Insecure Debug Stubs ({allSecrets.length})</span>
            </h3>
            <span className="text-xs text-slate-500">Entropy scan</span>
          </div>

          <div className="space-y-2.5">
            {allSecrets.map(({ asset, secret }) => {
              const isSelected = selectedSecret?.id === secret.id;
              return (
                <div
                  key={secret.id}
                  onClick={() => {
                    setSelectedSecret(secret);
                    setSelectedAssetId(asset.id);
                  }}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-emerald-50/70 border-emerald-500 dark:bg-slate-800/90 dark:border-emerald-400 shadow-sm'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <div>
                      <span className="font-bold text-xs text-slate-900 dark:text-slate-100">
                        {secret.type}
                      </span>
                      <span className="text-slate-400 text-xs mx-1.5">·</span>
                      <span className="text-slate-600 dark:text-slate-400 text-xs">{asset.name}</span>
                    </div>
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                        secret.severity === 'CRITICAL'
                          ? 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 border-rose-300 dark:border-rose-800/50'
                          : 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border-amber-300 dark:border-amber-800/50'
                      }`}
                    >
                      {secret.severity}
                    </span>
                  </div>

                  <div className="font-mono text-[11px] text-emerald-700 dark:text-emerald-400 truncate mb-1">
                    {secret.location}
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 line-clamp-2">
                    {secret.riskDescription}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Hex Dump & Secret Inspector (6 Cols) */}
        <div className="lg:col-span-6">
          {selectedSecret ? (
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4 sticky top-20">
              <div className="border-b border-slate-100 dark:border-slate-800 pb-3 flex items-start justify-between">
                <div>
                  <span className="text-[10px] font-bold text-rose-600 dark:text-rose-400 uppercase tracking-wider block">
                    {selectedSecret.type} Analysis
                  </span>
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                    {selectedSecret.location}
                  </h4>
                  <div className="text-xs text-slate-500 font-mono mt-0.5">
                    Device: {currentAsset.name} ({currentAsset.sector.toUpperCase()})
                  </div>
                </div>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800">
                  {selectedSecret.severity}
                </span>
              </div>

              {/* Memory Offset & Simulated Hex Dump */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span>Decompiled Memory Dump &amp; Extracted Token</span>
                </span>
                <div className="p-3.5 rounded-lg bg-slate-950 text-emerald-300 font-mono text-[11px] space-y-1 overflow-x-auto border border-slate-800">
                  <div className="text-slate-500 select-none">
                    // Memory Dump at {selectedSecret.location}
                  </div>
                  <pre className="whitespace-pre-wrap break-all">
                    {selectedSecret.snippet}
                  </pre>
                </div>
              </div>

              {/* Threat Impact */}
              <div className="p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-900/40 space-y-1">
                <span className="text-[10px] font-bold text-rose-800 dark:text-rose-400 uppercase tracking-wider block">
                  Supply Chain Threat &amp; Exploitability
                </span>
                <p className="text-xs text-rose-900 dark:text-rose-200/90 leading-relaxed">
                  {selectedSecret.riskDescription}
                </p>
              </div>

              {/* Recommended Engineering Action */}
              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-[10px] font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider block">
                  Remediation Action Required
                </span>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  {selectedSecret.type === 'Private RSA Key'
                    ? 'Revoke exposed private key immediately in OEM PKI infrastructure. Provision unique per-device keys inside Hardware Security Module (HSM/SHE) or ARM TrustZone.'
                    : selectedSecret.type === 'Hardcoded Password'
                    ? 'Eliminate shared default diagnostic creds. Enforce challenge-response asymmetric authentication per ISO/SAE 21434 and IEC 62443.'
                    : selectedSecret.type === 'Debug UART/JTAG Stub'
                    ? 'Disable debug USART handlers in production build configurations (#ifndef NDEBUG) and burn eFuses to disable hardware JTAG.'
                    : 'Rotate staging credentials and implement secure build pipeline attestation.'}
                </p>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-xs text-slate-500">
              No exposed secrets found in this firmware build.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
