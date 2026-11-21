
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import type { FirmwareAsset } from '../types/firmware';
import {
  generateCycloneDxVex,
  generateOpenVex
} from './vexExporter';
import {
  validateCycloneDxDocument,
  validateOpenVexDocument
} from './vexSchemaValidator';

function createAsset(): FirmwareAsset {
  return {
    id: 'asset-001',
    name: 'Industrial Controller',
    model: 'IC-500',
    manufacturer: 'FirmwareGuard',
    sector: 'energy',
    targetRole: 'Smart Substation RTU',
    version: '1.0.0',
    releaseDate: '2026-01-01',
    architecture: 'ARM Cortex-M4',
    osType: 'Embedded Linux (Yocto)',
    rawCveCount: 4,
    reachableCveCount: 1,
    cisaKevCount: 1,
    signatureStatus: 'Signed & Valid',
    mttrDays: 10,
    sbomCompletenessPercent: 100,
    hardening: {
      nxDep: true,
      aslrPie: true,
      stackCanary: true,
      relro: 'Full',
      fortifySource: true,
      strippedSymbols: true
    },
    secrets: [],
    components: [
      {
        id: 'component-001',
        name: 'OpenSSL',
        version: '3.0.0',
        layer: 'middleware',
        supplier: 'OpenSSL Foundation',
        tier: 'Tier 1',
        license: 'Apache-2.0',
        slsaLevel: 2,
        hashVerified: true,
        sha256: 'a'.repeat(64),
        cveCount: 2,
        reachableCveCount: 1,
        dependencies: ['component-002']
      },
      {
        id: 'component-002',
        name: 'Linux Kernel',
        version: '6.1.0',
        layer: 'rtos_kernel',
        supplier: 'Linux Foundation',
        tier: 'Tier 2',
        license: 'GPL-2.0-only',
        slsaLevel: 3,
        hashVerified: false,
        sha256: 'b'.repeat(64),
        cveCount: 2,
        reachableCveCount: 0,
        dependencies: []
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2024-10001',
        name: 'Reachable OpenSSL vulnerability',
        component: 'OpenSSL',
        version: '3.0.0',
        fixedVersion: '3.0.1',
        cvss: 9.8,
        epss: 0.89,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'The vulnerable function is reachable.',
        reachabilityPath: ['network', 'openssl', 'vulnerable_function']
      },
      {
        id: 'CVE-2024-10002',
        name: 'Unreachable vulnerability',
        component: 'OpenSSL',
        version: '3.0.0',
        cvss: 5.5,
        epss: 0.25,
        cisaKev: false,
        weaponizedPoc: false,
        vexStatus: 'affected_not_reachable',
        vexJustification: 'The vulnerable code is not in the execution path.'
      },
      {
        id: 'CVE-2024-10003',
        name: 'Vulnerable code not present',
        component: 'Linux Kernel',
        version: '6.1.0',
        cvss: 4.0,
        epss: 0.1,
        cisaKev: false,
        weaponizedPoc: false,
        vexStatus: 'not_affected',
        vexJustification: 'The vulnerable code is not present.',
        gridImpact: 'No grid impact identified.'
      },
      {
        id: 'CVE-2024-10004',
        name: 'Reported mitigation',
        component: 'Linux Kernel',
        version: '6.1.0',
        fixedVersion: '6.1.1',
        cvss: 7.5,
        epss: 0.6,
        cisaKev: false,
        weaponizedPoc: false,
        vexStatus: 'mitigated',
        vexJustification: 'A mitigation has been reported.',
        mitigation: 'Network access restricted.'
      }
    ],
    complianceGaps: []
  };
}

function parseJson<T = Record<string, any>>(value: string): T {
  return JSON.parse(value) as T;
}

describe('FirmwareGuard VEX exporter', () => {
  it('1. generates a valid CycloneDX document structure', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));

    assert.equal(result.bomFormat, 'CycloneDX');
    assert.equal(result.specVersion, '1.5');
    assert.equal(result.version, 1);
    assert.ok(result.serialNumber);
    assert.ok(result.metadata);
  });

  it('2. exports firmware product metadata and PURL', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const product = result.metadata.component;

    assert.equal(product.name, 'Industrial Controller');
    assert.equal(product.version, '1.0.0');
    assert.equal(
      product.purl,
      'pkg:generic/FirmwareGuard/IC-500@1.0.0'
    );
  });

  it('3. exports components with their supplied SHA-256 hashes', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const openssl = result.components.find(
      (component: any) => component.name === 'OpenSSL'
    );

    assert.ok(openssl);
    assert.equal(openssl.hashes[0].alg, 'SHA-256');
    assert.equal(openssl.hashes[0].content, 'a'.repeat(64));
  });

  it('4. omits an invalid SHA-256 value', () => {
    const asset = createAsset();
    asset.components[0].sha256 = 'invalid-hash';

    const result = parseJson(generateCycloneDxVex(asset));
    const openssl = result.components.find(
      (component: any) => component.name === 'OpenSSL'
    );

    assert.ok(openssl);
    assert.equal(openssl.hashes, undefined);
  });

  it('5. records hash verification as supplied assessment metadata', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));

    const openssl = result.components.find(
      (component: any) => component.name === 'OpenSSL'
    );
    const linux = result.components.find(
      (component: any) => component.name === 'Linux Kernel'
    );

    assert.ok(
      openssl.properties.some(
        (property: any) =>
          property.name === 'firmwareguard:evidence:hashVerification' &&
          property.value === 'verified_by_supplied_assessment'
      )
    );

    assert.ok(
      linux.properties.some(
        (property: any) =>
          property.name === 'firmwareguard:evidence:hashVerification' &&
          property.value === 'not_verified_by_supplied_assessment'
      )
    );
  });

  it('6. exports explicitly declared component dependencies', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));

    assert.ok(Array.isArray(result.dependencies));

    const opensslDependency = result.dependencies.find(
      (dependency: any) =>
        dependency.ref === 'firmwareguard-component-component-001'
    );

    assert.deepEqual(opensslDependency?.dependsOn, [
      'firmwareguard-component-component-002'
    ]);
  });

  it('7. omits unknown dependency references', () => {
    const asset = createAsset();
    asset.components[0].dependencies = ['unknown-component'];

    const result = parseJson(generateCycloneDxVex(asset));

    assert.equal(
      result.dependencies?.some(
        (dependency: any) =>
          dependency.ref === 'firmwareguard-component-component-001'
      ) ?? false,
      false
    );
  });

  it('8. maps reachable vulnerabilities to exploitable', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const vulnerability = result.vulnerabilities.find(
      (item: any) => item.id === 'CVE-2024-10001'
    );

    assert.equal(vulnerability.analysis.state, 'exploitable');
  });

  it('9. maps unreachable vulnerabilities to not_affected', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const vulnerability = result.vulnerabilities.find(
      (item: any) => item.id === 'CVE-2024-10002'
    );

    assert.equal(vulnerability.analysis.state, 'not_affected');
    assert.equal(
      vulnerability.analysis.justification,
      'code_not_reachable'
    );
  });

  it('10. maps reported mitigation to in_triage, not resolved', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const vulnerability = result.vulnerabilities.find(
      (item: any) => item.id === 'CVE-2024-10004'
    );

    assert.equal(vulnerability.analysis.state, 'in_triage');
    assert.notEqual(vulnerability.analysis.state, 'resolved');
  });

  it('11. exports CVE source and valid CVSS rating', () => {
    const result = parseJson(generateCycloneDxVex(createAsset()));
    const vulnerability = result.vulnerabilities.find(
      (item: any) => item.id === 'CVE-2024-10001'
    );

    assert.equal(
      vulnerability.source.url,
      'https://nvd.nist.gov/vuln/detail/CVE-2024-10001'
    );
    assert.equal(vulnerability.ratings[0].score, 9.8);
    assert.equal(vulnerability.ratings[0].severity, 'critical');
  });

  it('12. omits invalid CVSS and EPSS values', () => {
    const asset = createAsset();
    asset.vulnerabilities[0].cvss = 15;
    asset.vulnerabilities[0].epss = 2;

    const cycloneDx = parseJson(generateCycloneDxVex(asset));
    const vulnerability = cycloneDx.vulnerabilities.find(
      (item: any) => item.id === 'CVE-2024-10001'
    );

    assert.equal(vulnerability.ratings, undefined);
    assert.equal(
      vulnerability.properties.some(
        (property: any) => property.name === 'epss:score'
      ),
      false
    );
  });

  it('13. generates OpenVEX metadata and statements', () => {
    const result = parseJson(generateOpenVex(createAsset()));

    assert.equal(result['@context'], 'https://openvex.dev/ns/v0.2.0');
    assert.match(result['@id'], /^urn:uuid:/);
    assert.equal(result.author, 'FirmwareGuard Systems');
    assert.equal(result.version, 1);
    assert.equal(result.statements.length, 4);
  });

  it('14. maps OpenVEX statuses and does not claim mitigation is fixed', () => {
    const result = parseJson(generateOpenVex(createAsset()));

    const reachable = result.statements.find(
      (statement: any) =>
        statement.vulnerability.name === 'CVE-2024-10001'
    );
    const unreachable = result.statements.find(
      (statement: any) =>
        statement.vulnerability.name === 'CVE-2024-10002'
    );
    const notPresent = result.statements.find(
      (statement: any) =>
        statement.vulnerability.name === 'CVE-2024-10003'
    );
    const mitigated = result.statements.find(
      (statement: any) =>
        statement.vulnerability.name === 'CVE-2024-10004'
    );

    assert.equal(reachable.status, 'affected');
    assert.equal(unreachable.status, 'not_affected');
    assert.equal(
      unreachable.justification,
      'vulnerable_code_not_in_execute_path'
    );
    assert.equal(notPresent.status, 'not_affected');
    assert.equal(
      notPresent.justification,
      'vulnerable_code_not_present'
    );
    assert.equal(mitigated.status, 'under_investigation');
    assert.match(mitigated.status_notes, /Network access restricted/);
  });

  it('15. includes fixed-version information without claiming installation', () => {
    const result = parseJson(generateOpenVex(createAsset()));

    const statement = result.statements.find(
      (item: any) =>
        item.vulnerability.name === 'CVE-2024-10004'
    );

    assert.match(statement.status_notes, /6\.1\.1/);
    assert.match(statement.status_notes, /Installation has not been verified/);
    assert.notEqual(statement.status, 'fixed');
  });

  it('16. validates the generated CycloneDX document against its schema', () => {
    const document = parseJson(generateCycloneDxVex(createAsset()));
    const validation = validateCycloneDxDocument(document);

    assert.equal(
      validation.valid,
      true,
      `CycloneDX schema errors: ${validation.errors.join('; ')}`
    );
  });

  it('17. validates the generated OpenVEX document against its schema', () => {
    const document = parseJson(generateOpenVex(createAsset()));
    const validation = validateOpenVexDocument(document);

    assert.equal(
      validation.valid,
      true,
      `OpenVEX schema errors: ${validation.errors.join('; ')}`
    );
  });
});
