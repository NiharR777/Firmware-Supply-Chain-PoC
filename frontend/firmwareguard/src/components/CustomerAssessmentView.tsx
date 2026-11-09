
import React, { useState } from 'react';
import {
  UploadCloud,
  ShieldCheck,
  AlertTriangle,
  FileJson,
  Loader2,
} from 'lucide-react';

import { firmwareApi } from '../api/client';
import type { CustomerAssessmentResult } from '../api/client';

const createSampleCycloneDx = (productName: string) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    component: {
      type: 'application',
      name: productName.trim(),
      version: '3.2.0',
    },
  },
  components: [
    {
      type: 'library',
      name: 'openssl',
      version: '1.0.2u',
      purl: 'pkg:generic/openssl@1.0.2u',
    },
    {
      type: 'library',
      name: 'busybox',
      version: '1.30.0',
      purl: 'pkg:generic/busybox@1.30.0',
    },
    {
      type: 'library',
      name: 'zlib',
      version: '1.2.13',
      purl: 'pkg:generic/zlib@1.2.13',
    },
  ],
});

export const CustomerAssessmentView: React.FC = () => {
  const [industry, setIndustry] = useState<
    'industrial' | 'telecom' | 'healthcare'
  >('telecom');

  const [customer, setCustomer] = useState('Demo Telecom Customer');
  const [product, setProduct] = useState('Telecom_Router_X1');
  const [version, setVersion] = useState('3.2.0');

  const [hash, setHash] = useState('a'.repeat(64));
  const [baselineHash, setBaselineHash] = useState('b'.repeat(64));
  const [baselineVersion, setBaselineVersion] = useState('3.1.0');

  const [supplier, setSupplier] = useState('Example Device Supplier');
  const [source, setSource] = useState('Customer SBOM upload');

  const [sbomText, setSbomText] = useState(
    JSON.stringify(createSampleCycloneDx('Telecom_Router_X1'), null, 2)
  );

  const [result, setResult] =
    useState<CustomerAssessmentResult | null>(null);

  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState('');

  const loadSample = () => {
    const sample = createSampleCycloneDx(product);

    setSbomText(JSON.stringify(sample, null, 2));
    setFileName('Sample CycloneDX');
    setError('');
    setResult(null);
  };

  const loadFile = async (file?: File) => {
    if (!file) return;

    if (file.size > 2 * 1024 * 1024) {
      setError('SBOM file exceeds the 2 MB PoC limit.');
      return;
    }

    setFileName(file.name);
    setError('');
    setResult(null);

    setSbomText(await file.text());
  };

  const analyze = async () => {
    setBusy(true);
    setError('');
    setResult(null);

    try {
      const sbom = JSON.parse(sbomText);

      const response = await firmwareApi.customerAnalyze({
        industry,
        customer_name: customer,
        product_name: product.trim(),
        firmware_version: version,
        firmware_sha256: hash,
        approved_baseline_sha256: baselineHash || null,
        approved_baseline_version: baselineVersion || null,
        sbom,
        supplier_name: supplier,
        provenance_source: source,
      });

      setResult(response);
    } catch (e) {
      setError(
        e instanceof SyntaxError
          ? 'SBOM is not valid JSON. Check the file contents.'
          : e instanceof Error
            ? e.message
            : 'Assessment failed.'
      );
    } finally {
      setBusy(false);
    }
  };

  const field =
    'w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100';

  const label =
    'block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1';

  return (
    <div className="space-y-5">

      <div className="rounded-xl border border-cyan-200 dark:border-cyan-900 bg-cyan-50 dark:bg-cyan-950/30 p-4">
        <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <UploadCloud className="w-5 h-5 text-cyan-600" />
          Customer SBOM & Firmware Assessment
        </h2>

        <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
          Upload CycloneDX or SPDX JSON, validate metadata, match
          components against the PoC vulnerability catalog and compare
          submitted firmware metadata with the customer's approved baseline.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-3">

          <h3 className="font-bold text-sm text-slate-900 dark:text-white">
            1. Customer and firmware metadata
          </h3>

          <div>
            <label className={label}>Industry profile</label>

            <select
              className={field}
              value={industry}
              onChange={(e) =>
                setIndustry(e.target.value as typeof industry)
              }
            >
              <option value="industrial">Industrial / IIoT</option>
              <option value="telecom">Telecommunications</option>
              <option value="healthcare">Healthcare / Medical devices</option>
            </select>
          </div>

          <div>
            <label className={label}>Customer name</label>
            <input
              className={field}
              value={customer}
              onChange={(e) => setCustomer(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>Product / device name</label>
            <input
              className={field}
              value={product}
              onChange={(e) => setProduct(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>Submitted firmware version</label>
            <input
              className={field}
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>
              Submitted firmware SHA-256 (64 hex characters)
            </label>
            <input
              className={`${field} font-mono text-xs`}
              value={hash}
              onChange={(e) => setHash(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>
              Approved baseline SHA-256 (optional)
            </label>
            <input
              className={`${field} font-mono text-xs`}
              value={baselineHash}
              onChange={(e) => setBaselineHash(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>
              Approved baseline version (optional)
            </label>
            <input
              className={field}
              value={baselineVersion}
              onChange={(e) => setBaselineVersion(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>Supplier / vendor</label>
            <input
              className={field}
              value={supplier}
              onChange={(e) => setSupplier(e.target.value)}
            />
          </div>

          <div>
            <label className={label}>Provenance source</label>
            <input
              className={field}
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />
          </div>

        </section>

        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-3">

          <h3 className="font-bold text-sm text-slate-900 dark:text-white">
            2. SBOM intake
          </h3>

          <label className="flex items-center justify-center gap-2 rounded-lg border-2 border-dashed border-slate-300 dark:border-slate-700 p-5 text-sm cursor-pointer hover:border-cyan-500 text-slate-600 dark:text-slate-300">
            <FileJson className="w-5 h-5" />
            Choose CycloneDX / SPDX JSON file

            <input
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => loadFile(e.target.files?.[0])}
            />
          </label>

          <p className="text-xs text-slate-500">
            {fileName ||
              'No file selected. Use the sample SBOM or paste JSON below.'}
            {' '}· Maximum 2 MB
          </p>

          <div className="flex justify-between items-center">
            <label className={label}>SBOM JSON content</label>

            <button
              type="button"
              className="text-xs text-cyan-600 hover:underline"
              onClick={loadSample}
            >
              Load sample
            </button>
          </div>

          <textarea
            className={`${field} font-mono text-xs`}
            rows={18}
            value={sbomText}
            onChange={(e) => setSbomText(e.target.value)}
            spellCheck={false}
          />

          <button
            type="button"
            disabled={busy}
            onClick={analyze}
            className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm py-3 flex items-center justify-center gap-2"
          >
            {busy ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing SBOM...
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                Validate and assess customer SBOM
              </>
            )}
          </button>

          {error && (
            <div className="rounded-lg bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900 p-3 text-sm text-rose-700 dark:text-rose-300">
              {error}
            </div>
          )}

        </section>

      </div>

      {result && (
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-4">

          <div className="flex flex-wrap justify-between gap-3 items-start">

            <div>
              <h3 className="font-bold text-slate-900 dark:text-white">
                3. Assessment findings
              </h3>

              <p className="text-xs text-slate-500">
                {result.assessment_id} · {result.sbom_format} ·{' '}
                {result.component_count} components
              </p>
            </div>

            <div className="text-right">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {result.risk.score}/100
              </div>

              <span className="text-xs uppercase font-bold text-amber-600">
                {result.risk.level} risk
              </span>
            </div>

          </div>

          <div className="grid sm:grid-cols-3 gap-3">

            <div className="rounded-lg bg-slate-50 dark:bg-slate-950 p-3">
              <div className="text-xs text-slate-500">
                SBOM completeness
              </div>
              <div className="font-semibold">
                {result.completeness}
              </div>
            </div>

            <div className="rounded-lg bg-slate-50 dark:bg-slate-950 p-3">
              <div className="text-xs text-slate-500">
                Product mapping
              </div>
              <div className="font-semibold">
                {result.product_mapping.mapped
                  ? 'Matched'
                  : 'Needs review'}
              </div>
            </div>

            <div className="rounded-lg bg-slate-50 dark:bg-slate-950 p-3">
              <div className="text-xs text-slate-500">
                Baseline comparison
              </div>
              <div className="font-semibold">
                {result.baseline_comparison.status}
              </div>
            </div>

          </div>

          <div>
            <h4 className="font-semibold text-sm mb-2">
              Component vulnerability matches
            </h4>

            {result.vulnerability_matching.findings.length ? (
              <div className="space-y-2">

                {result.vulnerability_matching.findings.map((f, i) => (
                  <div
                    key={i}
                    className="border border-amber-200 dark:border-amber-900 rounded-lg p-3"
                  >
                    <div className="flex justify-between gap-2 text-sm font-semibold">
                      <span>{f.component} {f.version}</span>

                      <span className="uppercase text-amber-600">
                        {f.severity}
                      </span>
                    </div>

                    <p className="text-xs text-slate-500 mt-1">
                      {f.demo_id} · {f.description}
                    </p>

                    <p className="text-xs mt-1">
                      {f.recommendation}
                    </p>
                  </div>
                ))}

              </div>
            ) : (
              <p className="text-sm text-slate-500">
                No matches in the current synthetic demonstration catalog.
                This is not proof that the SBOM has no vulnerabilities.
              </p>
            )}
          </div>

          {result.vulnerability_matching.live_nvd && (
            <section className="rounded-xl border border-cyan-200 dark:border-cyan-900 bg-cyan-50/50 dark:bg-cyan-950/20 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h4 className="font-bold text-sm text-slate-900 dark:text-white">
                    Live NVD Vulnerability Intelligence
                  </h4>
                  <p className="text-xs text-slate-500 mt-1">
                    {result.vulnerability_matching.live_nvd.provider}
                    {' '}? {result.vulnerability_matching.live_nvd.components_checked} components checked
                    {' '}? {result.vulnerability_matching.live_nvd.findings_count} candidate CVEs
                  </p>
                </div>
                <span className="rounded-full bg-cyan-100 dark:bg-cyan-900/50 px-3 py-1 text-xs font-semibold text-cyan-800 dark:text-cyan-200">
                  {result.vulnerability_matching.live_nvd.is_live_source ? 'Live source' : 'Source unavailable'}
                </span>
              </div>

              <div className="rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3">
                <p className="text-xs font-bold text-amber-800 dark:text-amber-200">
                  Candidate CVEs ? Applicability Not Verified
                </p>
                <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
                  Keyword results do not confirm that this firmware or product is affected.
                  Verify the exact product, affected version, configuration and vendor advisory.
                </p>
              </div>

              {result.vulnerability_matching.live_nvd.findings.length > 0 ? (
                <div className="space-y-3">
                  {result.vulnerability_matching.live_nvd.findings.map((f) => (
                    <article
                      key={`${f.cve_id}-${f.component}`}
                      className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 space-y-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <span className="font-bold text-sm text-cyan-700 dark:text-cyan-300">
                            {f.cve_id}
                          </span>
                          <span className="text-xs text-slate-500 ml-2">
                            {f.component} {f.version}
                          </span>
                        </div>
                        <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-1 text-xs font-bold uppercase text-slate-700 dark:text-slate-200">
                          {f.severity}
                          {f.cvss_score !== null ? ` ? ${f.cvss_score} CVSS` : ''}
                        </span>
                      </div>

                      <p className="text-xs text-slate-600 dark:text-slate-300">
                        {f.description}
                      </p>

                      <p className="text-xs text-amber-700 dark:text-amber-300">
                        {f.recommendation}
                      </p>

                      <div className="flex flex-wrap gap-3 text-xs">
                        {f.references.slice(0, 4).map((url, index) => (
                          <a
                            key={`${f.cve_id}-ref-${index}`}
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-700 dark:text-cyan-300 hover:underline break-all"
                          >
                            NVD / advisory reference {index + 1}
                          </a>
                        ))}
                      </div>

                      <div className="text-xs text-slate-500">
                        Status: {f.match_status.replaceAll('_', ' ')}
                        {' '}? Applicability verified: No
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500">
                  No NVD candidate CVEs were returned for the checked components.
                  This does not prove that the components are vulnerability-free.
                </p>
              )}

              {result.vulnerability_matching.live_nvd.errors.length > 0 && (
                <div className="rounded-lg border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/30 p-3">
                  <p className="text-xs font-semibold text-rose-700 dark:text-rose-300">
                    NVD lookup warnings
                  </p>
                  {result.vulnerability_matching.live_nvd.errors.map((error, index) => (
                    <p key={index} className="text-xs text-rose-700 dark:text-rose-300 mt-1">
                      {error}
                    </p>
                  ))}
                </div>
              )}

              <p className="text-xs text-slate-500">
                {result.vulnerability_matching.live_nvd.applicability_note}
              </p>
            </section>
          )}

          <div className="rounded-lg bg-slate-50 dark:bg-slate-950 p-3">
            <h4 className="font-semibold text-sm mb-2">
              Analyst recommendation:{' '}
              {result.recommendation.replaceAll('_', ' ')}
            </h4>

            <p className="text-xs text-slate-500">
              Human review required: Yes · Deployment allowed: No ·
              Real action executed: No
            </p>
          </div>

          <div className="rounded-lg border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-950/20 p-3 text-xs text-amber-800 dark:text-amber-200">

            <div className="font-bold flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4" />
              PoC limitations
            </div>

            <ul className="list-disc pl-5 space-y-1">
              {result.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>

          </div>

        </section>
      )}

    </div>
  );
};
