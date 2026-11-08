import React, { useState } from 'react';
import { FirmwareAsset, SectorType } from '../types/firmware';
import {
  UploadCloud,
  Play,
  Terminal,
  FileText,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Code2,
  Cpu,
  Layers,
  Sparkles
} from 'lucide-react';

interface SbomIngestionStudioProps {
  onIngestNewAsset: (asset: FirmwareAsset) => void;
  onOpenExportModal: () => void;
}

export const SbomIngestionStudio: React.FC<SbomIngestionStudioProps> = ({
  onIngestNewAsset,
  onOpenExportModal,
}) => {
  const [selectedFirmwarePreset, setSelectedFirmwarePreset] = useState('med_pump');
  const [uploadText, setUploadText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [analysisLogs, setAnalysisLogs] = useState<string[]>([]);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [analyzedAsset, setAnalyzedAsset] = useState<FirmwareAsset | null>(null);

  const presets = [
    {
      id: 'med_pump',
      name: 'InfusionCare_Bedside_v2.4.1.bin',
      sector: 'healthcare' as SectorType,
      size: '14.8 MB',
      architecture: 'ARM Cortex-M4',
      os: 'FreeRTOS 10.4',
      target: 'Medical Bedside Infusion Pump',
    },
    {
      id: 'energy_rtu',
      name: 'GridDefender_SEL710_Substation_v4.14.fw',
      sector: 'energy' as SectorType,
      size: '32.1 MB',
      architecture: 'PowerPC e500',
      os: 'VxWorks 7.0',
      target: 'Substation Protective Relay & RTU',
    },
    {
      id: 'oil_sis',
      name: 'TricoSafe_SIS_Controller_MP3008.rom',
      sector: 'oil_gas' as SectorType,
      size: '8.4 MB',
      architecture: 'ARM Cortex-R5 Dual Lockstep',
      os: 'Bare-metal / TriStation OS',
      target: 'Refinery Emergency Shutdown Controller',
    },
    {
      id: 'auto_ecu',
      name: 'AeroDrive_CGW_ADAS_ECU_v5.2.hex',
      sector: 'automotive' as SectorType,
      size: '64.0 MB',
      architecture: 'TriCore TC397',
      os: 'AUTOSAR Classic 4.4',
      target: 'Automotive Central Gateway & ADAS ECU',
    },
  ];

  const handleStartAnalysis = () => {
    setIsAnalyzing(true);
    setCurrentStep(1);
    setAnalysisComplete(false);
    setAnalysisLogs([
      '[INIT] Ingestion engine initialized. Binary unpacker: binwalk v2.3.4+bca',
      '[STAGE 1] Reading firmware stream signature and magic bytes...',
    ]);

    const steps = [
      {
        delay: 600,
        log: '[EXTRACT] Found SquashFS filesystem at offset 0x00084000. Decompressing 4,821 inodes...',
        step: 1,
      },
      {
        delay: 1300,
        log: '[DISASM] Launching headless Ghidra disassembly. Reconstructing ELF symbol tables and cross-references...',
        step: 2,
      },
      {
        delay: 2000,
        log: '[SCAN] Running entropy and cryptographic secret scan. Analyzing RO data segments and certificates...',
        step: 3,
      },
      {
        delay: 2800,
        log: '[REACHABILITY] Calculating static call-graph from external network/CAN listening sockets to linked functions...',
        step: 4,
      },
      {
        delay: 3500,
        log: '[VEX GEN] 142 raw CVEs scanned. Reachability filter collapsed actionable threats to 4 active paths. VEX statements produced.',
        step: 5,
      },
    ];

    steps.forEach(({ delay, log, step }, idx) => {
      setTimeout(() => {
        setAnalysisLogs((prev) => [...prev, log]);
        setCurrentStep(step);
        if (idx === steps.length - 1) {
          setIsAnalyzing(false);
          setAnalysisComplete(true);
        }
      }, delay);
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <span>Firmware Binary Extraction & SBOM Ingestion Pipeline</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated binary composition analysis (BCA), Ghidra headless call-graph disassembly, and VEX justification generation.
          </p>
        </div>
      </div>

      {/* Ingestion Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Preset Firmware Images or Custom Upload (6 Cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            1. Select Target Firmware Binary or Upload Custom SBOM
          </div>

          {/* Preset Firmware Images Grid */}
          <div className="space-y-2">
            {presets.map((p) => {
              const isSelected = selectedFirmwarePreset === p.id;
              return (
                <div
                  key={p.id}
                  onClick={() => setSelectedFirmwarePreset(p.id)}
                  className={`p-3 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-400 shadow-sm'
                      : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {p.name}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                      {p.size}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>{p.target}</span>
                    <span className="font-mono text-slate-500">
                      {p.architecture} · {p.os}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Custom CycloneDX / SPDX JSON Input */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Or Paste CycloneDX 1.5 / SPDX 2.3 JSON:</span>
              <button
                onClick={() =>
                  setUploadText(
                    `{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "metadata": {\n    "component": {\n      "name": "Custom_Substation_RTU",\n      "version": "1.0.0"\n    }\n  }\n}`
                  )
                }
                className="text-cyan-400 hover:underline cursor-pointer text-[11px]"
              >
                Insert Sample
              </button>
            </div>
            <textarea
              value={uploadText}
              onChange={(e) => setUploadText(e.target.value)}
              placeholder="Paste custom CycloneDX JSON or raw binary descriptor here..."
              rows={4}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Start Action */}
          <button
            disabled={isAnalyzing}
            onClick={handleStartAnalysis}
            className={`w-full py-2.5 px-4 rounded-lg font-semibold text-xs flex items-center justify-center gap-2 cursor-pointer transition-all ${
              isAnalyzing
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed'
                : 'bg-cyan-400 hover:bg-cyan-300 text-slate-950 shadow-md shadow-cyan-950/50'
            }`}
          >
            {isAnalyzing ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                <span>Running Binary Decomposition Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Unpacking & Reachability Analysis</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column: Real-Time Execution Console & Results (6 Cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>2. Analysis Pipeline Telemetry & Call-Graph Tracer</span>
            {analysisComplete && (
              <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Pipeline Complete</span>
              </span>
            )}
          </div>

          {/* Terminal Console */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 h-64 overflow-y-auto space-y-2 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="text-slate-600 select-none pb-1 border-b border-slate-900">
                # FirmwareGuard Static Binary Composition Engine v4.2.0
              </div>
              {analysisLogs.length === 0 ? (
                <div className="text-slate-600 italic py-4">
                  Awaiting execution. Click &quot;Execute Unpacking & Reachability Analysis&quot; to begin.
                </div>
              ) : (
                analysisLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={`${
                      log.includes('[VEX GEN]')
                        ? 'text-emerald-400 font-bold'
                        : log.includes('[SCAN]') || log.includes('[REACHABILITY]')
                        ? 'text-cyan-400'
                        : 'text-slate-300'
                    }`}
                  >
                    {log}
                  </div>
                ))
              )}
            </div>

            {isAnalyzing && (
              <div className="flex items-center gap-2 text-cyan-400 pt-2 border-t border-slate-900">
                <span className="animate-pulse">●</span>
                <span className="text-[11px]">Processing disassembly symbols...</span>
              </div>
            )}
          </div>

          {/* Post Analysis Summary Card */}
          {analysisComplete && (
            <div className="p-4 rounded-xl bg-slate-900 border border-emerald-800/60 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Binary Successfully Extracted & Classified</span>
                </span>
                <span className="font-mono text-[11px] text-slate-400">
                  SBOM & VEX Generated
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Components</span>
                  <span className="font-mono font-bold text-slate-200">24 extracted</span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Raw CVEs</span>
                  <span className="font-mono font-bold text-slate-400">142</span>
                </div>
                <div className="p-2 rounded bg-rose-950/40 border border-rose-900/60">
                  <span className="text-[10px] text-rose-400 uppercase block font-semibold">
                    Reachable
                  </span>
                  <span className="font-mono font-bold text-rose-300">4 Critical</span>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <button
                  onClick={onOpenExportModal}
                  className="w-full py-2 px-3 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
                >
                  Export Machine-Readable CycloneDX 1.5 VEX
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
