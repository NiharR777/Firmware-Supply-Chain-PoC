import React, { useState } from 'react';
import { FirmwareAsset } from '../types/firmware';
import { generateCycloneDxVex, generateOpenVex } from '../utils/vexExporter';
import {
  X,
  Download,
  Copy,
  Check,
  FileCode,
  ShieldCheck,
  FileCheck
} from 'lucide-react';

interface VexExporterModalProps {
  isOpen: boolean;
  onClose: () => void;
  assets: FirmwareAsset[];
}

export const VexExporterModal: React.FC<VexExporterModalProps> = ({
  isOpen,
  onClose,
  assets,
}) => {
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');
  const [format, setFormat] = useState<'cyclonedx' | 'openvex'>('cyclonedx');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const currentAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const jsonContent =
    format === 'cyclonedx'
      ? generateCycloneDxVex(currentAsset)
      : generateOpenVex(currentAsset);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const filename = `${currentAsset.name.toLowerCase().replace(/\s+/g, '_')}_${format}_vex.json`;
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const reachableCount = currentAsset.vulnerabilities.filter(
    (v) => v.vexStatus === 'affected_reachable'
  ).length;
  const suppressedCount = currentAsset.vulnerabilities.length - reachableCount;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <FileCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>Automated VEX Justification Exporter</span>
                <span className="text-xs font-mono font-normal text-slate-400">
                  (FDA 524B & NERC CIP-013 Standard)
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Generate machine-readable vulnerability exploitability exchange documents for regulators.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Controls Bar */}
        <div className="p-4 bg-slate-950/70 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          {/* Target Asset Selector */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400 font-medium">Device Firmware:</label>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.model}) - {a.sector.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          {/* Format Picker */}
          <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setFormat('cyclonedx')}
              className={`px-3 py-1 rounded-md text-xs font-semibold cursor-pointer transition-colors ${
                format === 'cyclonedx'
                  ? 'bg-cyan-500 text-slate-950 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              CycloneDX 1.5 VEX
            </button>
            <button
              onClick={() => setFormat('openvex')}
              className={`px-3 py-1 rounded-md text-xs font-semibold cursor-pointer transition-colors ${
                format === 'openvex'
                  ? 'bg-cyan-500 text-slate-950 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              OpenVEX v0.2.0
            </button>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy JSON</span>
                </>
              )}
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .json</span>
            </button>
          </div>
        </div>

        {/* Audit Justification Banner */}
        <div className="px-5 py-2.5 bg-slate-950/40 border-b border-slate-800 flex items-center justify-between text-xs">
          <div className="flex items-center gap-3">
            <span className="text-slate-400">
              VEX Statements for {currentAsset.vulnerabilities.length} vulnerabilities:
            </span>
            <span className="font-mono text-rose-400 font-bold">
              {reachableCount} Exploitable
            </span>
            <span className="text-slate-600">·</span>
            <span className="font-mono text-emerald-400 font-bold">
              {suppressedCount} Suppressed / Justified
            </span>
          </div>
          <span className="text-slate-500 font-mono text-[11px]">
            Schema: {format === 'cyclonedx' ? 'CycloneDX 1.5 JSON' : 'OpenVEX 0.2'}
          </span>
        </div>

        {/* Monospace Code Body */}
        <div className="flex-1 overflow-y-auto p-4 bg-slate-950 font-mono text-xs text-slate-300">
          <pre className="whitespace-pre overflow-x-auto leading-relaxed select-text">
            {jsonContent}
          </pre>
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-slate-900 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <span>
            Complies with CISA VEX minimum requirements and NTIA framing guidance.
          </span>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
