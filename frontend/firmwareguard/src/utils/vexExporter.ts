
import { FirmwareAsset } from '../types/firmware';

type CycloneDxState = 'exploitable' | 'not_affected' | 'in_triage';

type OpenVexStatus =
  | 'affected'
  | 'not_affected'
  | 'under_investigation';

type ValidationProperty = {
  name: string;
  value: string;
};

function createUuid(): string {
  if (
    typeof crypto !== 'undefined' &&
    typeof crypto.randomUUID === 'function'
  ) {
    return crypto.randomUUID();
  }

  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
    /[xy]/g,
    (character) => {
      const random = Math.floor(Math.random() * 16);
      const value = character === 'x' ? random : (random & 0x3) | 0x8;
      return value.toString(16);
    }
  );
}

function cleanString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  const cleaned = value.trim();
  return cleaned.length > 0 ? cleaned : undefined;
}

function purlSegment(value: string): string {
  return encodeURIComponent(value.trim()).replace(
    /[!'()*]/g,
    (character) =>
      `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function createProductPurl(asset: FirmwareAsset): string {
  const manufacturer = purlSegment(
    cleanString(asset.manufacturer) ?? 'unknown-manufacturer'
  );

  const model = purlSegment(
    cleanString(asset.model) ?? asset.id
  );

  const version = purlSegment(
    cleanString(asset.version) ?? 'unknown'
  );

  return `pkg:generic/${manufacturer}/${model}@${version}`;
}

function createProductIri(asset: FirmwareAsset): string {
  const manufacturer = encodeURIComponent(
    cleanString(asset.manufacturer) ?? 'unknown-manufacturer'
  );

  const model = encodeURIComponent(
    cleanString(asset.model) ?? asset.id
  );

  const version = encodeURIComponent(
    cleanString(asset.version) ?? 'unknown'
  );

  return `https://firmwareguard.example/products/${manufacturer}/${model}/versions/${version}`;
}

function createComponentPurl(
  name: string,
  version: string
): string {
  return `pkg:generic/${purlSegment(name)}@${purlSegment(version)}`;
}

function isValidSha256(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[a-fA-F0-9]{64}$/.test(value.trim())
  );
}

function isValidCvss(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 10
  );
}

function isValidEpss(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function getCvssSeverity(score: number): string {
  if (score === 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

function getCycloneDxAnalysis(vexStatus: string): {
  state: CycloneDxState;
  justification?: string;
} {
  switch (vexStatus) {
    case 'affected_reachable':
      return {
        state: 'exploitable'
      };

    case 'affected_not_reachable':
      return {
        state: 'not_affected',
        justification: 'code_not_reachable'
      };

    case 'not_affected':
      return {
        state: 'not_affected',
        justification: 'code_not_present'
      };

    case 'mitigated':
    default:
      // A reported mitigation is not proof of completed remediation.
      return {
        state: 'in_triage'
      };
  }
}

function getOpenVexAnalysis(vexStatus: string): {
  status: OpenVexStatus;
  justification?: string;
  actionStatement?: string;
  statusNotes: string;
} {
  switch (vexStatus) {
    case 'affected_reachable':
      return {
        status: 'affected',
        actionStatement:
          'Review the OEM security advisory and plan an approved remediation or mitigation.',
        statusNotes:
          'The supplied assessment classifies this finding as reachable. Independent verification is not performed by this exporter.'
      };

    case 'affected_not_reachable':
      return {
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        statusNotes:
          'The supplied assessment classifies the vulnerable code as not reachable. This exporter does not independently verify binary reachability.'
      };

    case 'not_affected':
      return {
        status: 'not_affected',
        justification: 'vulnerable_code_not_present',
        statusNotes:
          'The supplied assessment classifies the vulnerable code as not present. This exporter does not independently verify binary contents.'
      };

    case 'mitigated':
    default:
      return {
        status: 'under_investigation',
        statusNotes:
          'A mitigation is reported, but complete remediation has not been independently verified. Further review is required.'
      };
  }
}

function getVulnerabilityProperties(
  vuln: FirmwareAsset['vulnerabilities'][number]
): ValidationProperty[] {
  const properties: ValidationProperty[] = [];

  if (isValidEpss(vuln.epss)) {
    properties.push({
      name: 'epss:score',
      value: String(vuln.epss)
    });
  }

  if (typeof vuln.cisaKev === 'boolean') {
    properties.push({
      name: 'cisa:kev',
      value: String(vuln.cisaKev)
    });
  }

  if (typeof vuln.weaponizedPoc === 'boolean') {
    properties.push({
      name: 'firmware:weaponizedPoc',
      value: String(vuln.weaponizedPoc)
    });
  }

  if (
    Array.isArray(vuln.reachabilityPath) &&
    vuln.reachabilityPath.length > 0
  ) {
    properties.push({
      name: 'reachability:suppliedPath',
      value: vuln.reachabilityPath.join(' -> ')
    });
  }

  const fixedVersion = cleanString(vuln.fixedVersion);

  if (fixedVersion) {
    properties.push({
      name: 'firmwareguard:remediation:fixedVersion',
      value: fixedVersion
    });
  }

  return properties;
}

/**
 * Generates a CycloneDX 1.5 document containing VEX analysis.
 *
 * This exporter formats supplied assessment data. It does not independently
 * scan firmware, verify signatures, prove reachability, authenticate
 * component provenance, or verify that a fixed version is installed.
 */
export function generateCycloneDxVex(asset: FirmwareAsset): string {
  const documentId = createUuid();
  const timestamp = new Date().toISOString();
  const productPurl = createProductPurl(asset);
  const rootComponentRef = `firmwareguard-product-${asset.id}`;

  const components = (asset.components ?? []).map((component, index) => {
    const name =
      cleanString(component.name) ?? `component-${index + 1}`;

    const version = cleanString(component.version) ?? 'unknown';
    const componentRef = `firmwareguard-component-${component.id || index}`;

    const componentObject: Record<string, unknown> = {
      'bom-ref': componentRef,
      type: component.layer === 'silicon_bsp' ? 'device' : 'library',
      name,
      version,
      purl: createComponentPurl(name, version),
      supplier: {
        name: cleanString(component.supplier) ?? 'Unknown supplier'
      },
      properties: [
        {
          name: 'firmwareguard:evidence:slsaLevel',
          value: String(component.slsaLevel)
        },
        {
          name: 'firmwareguard:evidence:supplyChainTier',
          value: String(component.tier)
        },
        {
          name: 'firmwareguard:evidence:hashVerification',
          value: component.hashVerified
            ? 'verified_by_supplied_assessment'
            : 'not_verified_by_supplied_assessment'
        }
      ]
    };

    if (isValidSha256(component.sha256)) {
      componentObject.hashes = [
        {
          alg: 'SHA-256',
          content: component.sha256.trim().toLowerCase()
        }
      ];
    }

    const license = cleanString(component.license);

    if (license) {
      componentObject.licenses = [
        {
          license: {
            id: license
          }
        }
      ];
    }

    return {
      id: component.id,
      ref: componentRef,
      name,
      version,
      object: componentObject
    };
  });

  const componentRefs = new Map(
    components.map((component) => [
      component.id,
      component.ref
    ])
  );

  const componentRefsByNameAndVersion = new Map(
    components.map((component) => [
      `${component.name.toLowerCase()}@${component.version.toLowerCase()}`,
      component.ref
    ])
  );

  const cycloneDxComponents = components.map(
    (component) => component.object
  );

  // Export only dependency relationships explicitly supplied by the asset.
  // Unknown dependency IDs are omitted rather than assigned invented references.
  const dependencies = components.flatMap((component) => {
    const declaredDependencies =
      asset.components.find((item) => item.id === component.id)
        ?.dependencies ?? [];

    const dependsOn = declaredDependencies
      .map((dependencyId) => componentRefs.get(dependencyId))
      .filter((ref): ref is string => Boolean(ref));

    if (dependsOn.length === 0) {
      return [];
    }

    return [
      {
        ref: component.ref,
        dependsOn: [...new Set(dependsOn)]
      }
    ];
  });

  const vulnerabilities = (asset.vulnerabilities ?? []).map((vuln) => {
    const analysis = getCycloneDxAnalysis(vuln.vexStatus);

    const componentName = cleanString(vuln.component);
    const componentVersion = cleanString(vuln.version);

    const matchedRef =
      componentName && componentVersion
        ? componentRefsByNameAndVersion.get(
            `${componentName.toLowerCase()}@${componentVersion.toLowerCase()}`
          )
        : undefined;

    const vulnerabilityObject: Record<string, unknown> = {
      id: vuln.id,
      description: cleanString(vuln.name) ?? vuln.id,
      analysis: {
        state: analysis.state,
        detail:
          cleanString(vuln.vexJustification) ??
          'Assessment details supplied by the FirmwareGuard demonstration dataset.',
        ...(analysis.justification
          ? { justification: analysis.justification }
          : {})
      },
      affects: [
        {
          // If the component cannot be matched, reference the product.
          ref: matchedRef ?? rootComponentRef
        }
      ],
      properties: getVulnerabilityProperties(vuln)
    };

    if (/^CVE-\d{4}-\d{4,}$/i.test(vuln.id)) {
      vulnerabilityObject.source = {
        name: 'National Vulnerability Database',
        url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.id)}`
      };
    }

    if (isValidCvss(vuln.cvss)) {
      vulnerabilityObject.ratings = [
        {
          score: vuln.cvss,
          severity: getCvssSeverity(vuln.cvss)
        }
      ];
    }

    if (analysis.state === 'in_triage') {
      vulnerabilityObject.analysis = {
        ...(vulnerabilityObject.analysis as Record<string, unknown>),
        detail:
          'A mitigation is reported, but complete remediation has not been independently verified. Human review is required.'
      };
    }

    return vulnerabilityObject;
  });

  const cycloneDxObject: Record<string, unknown> = {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${documentId}`,
    version: 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: 'FirmwareGuard Systems',
          name: 'FirmwareGuard VEX Exporter',
          version: '1.0.0'
        }
      ],
      component: {
        'bom-ref': rootComponentRef,
        type: 'firmware',
        name: asset.name,
        version: asset.version,
        purl: productPurl,
        properties: [
          { name: 'firmware:sector', value: asset.sector },
          { name: 'firmware:architecture', value: asset.architecture },
          { name: 'firmware:osType', value: asset.osType },
          {
            name: 'firmwareguard:evidence:provenance',
            value: 'Supplied demonstration data; not independently attested'
          }
        ]
      }
    },
    components: cycloneDxComponents,
    vulnerabilities
  };

  if (dependencies.length > 0) {
    cycloneDxObject.dependencies = dependencies;
  }

  return JSON.stringify(cycloneDxObject, null, 2);
}

/**
 * Generates an OpenVEX v0.2.0 JSON document.
 *
 * The document describes supplied assessment results. It does not claim
 * that the exporter itself performed binary reachability analysis or
 * verified that a remediation has been installed.
 */
export function generateOpenVex(asset: FirmwareAsset): string {
  const documentId = createUuid();
  const timestamp = new Date().toISOString();
  const productIri = createProductIri(asset);

  const statements = (asset.vulnerabilities ?? []).map((vuln) => {
    const analysis = getOpenVexAnalysis(vuln.vexStatus);

    const statement: Record<string, unknown> = {
      vulnerability: {
        name: vuln.id
      },
      products: [
        {
          '@id': productIri
        }
      ],
      status: analysis.status,
      status_notes: analysis.statusNotes
    };

    if (/^CVE-\d{4}-\d{4,}$/i.test(vuln.id)) {
      (statement.vulnerability as Record<string, unknown>)['@id'] =
        `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.id)}`;
    }

    if (analysis.justification) {
      statement.justification = analysis.justification;
    }

    const fixedVersion = cleanString(vuln.fixedVersion);

    if (analysis.actionStatement) {
      statement.action_statement = fixedVersion
        ? `${analysis.actionStatement} Fixed version identified by supplied assessment: ${fixedVersion}. Confirm the approved update is installed before treating the finding as remediated.`
        : analysis.actionStatement;
    }

    const impactStatement =
      cleanString(vuln.clinicalImpact) ??
      cleanString(vuln.gridImpact) ??
      cleanString(vuln.safetyImpact) ??
      cleanString(vuln.vexJustification);

    if (analysis.status === 'not_affected' && impactStatement) {
      statement.impact_statement = impactStatement;
    }

    if (analysis.status === 'under_investigation') {
      const mitigation = cleanString(vuln.mitigation);
      const remediationVersion = fixedVersion
        ? `Fixed version identified by supplied assessment: ${fixedVersion}. Installation has not been verified.`
        : '';

      statement.status_notes = [
        analysis.statusNotes,
        mitigation ? `Reported mitigation: ${mitigation}` : '',
        remediationVersion
      ]
        .filter(Boolean)
        .join(' ');
    }

    return statement;
  });

  const openVexObject = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${documentId}`,
    author: 'FirmwareGuard Systems',
    role: 'VEX document generator',
    timestamp,
    version: 1,
    statements
  };

  return JSON.stringify(openVexObject, null, 2);
}
