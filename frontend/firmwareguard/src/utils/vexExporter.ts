import { FirmwareAsset, Vulnerability } from '../types/firmware';

/**
 * Generates an official CycloneDX 1.5 JSON document containing VEX analysis
 */
export function generateCycloneDxVex(asset: FirmwareAsset): string {
  const cycloneDxObj = {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : '847291a2-3b12-4f1e-9238-1a0982348571'}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'FirmwareGuard Systems',
          name: 'Firmware Binary Composition & Reachability Analyzer',
          version: '4.2.0'
        }
      ],
      component: {
        type: 'firmware',
        name: asset.name,
        version: asset.version,
        purl: `pkg:firmware/${asset.manufacturer.toLowerCase().replace(/\s+/g, '-')}/${asset.model.toLowerCase()}@${asset.version}`,
        properties: [
          { name: 'firmware:sector', value: asset.sector },
          { name: 'firmware:architecture', value: asset.architecture },
          { name: 'firmware:osType', value: asset.osType }
        ]
      }
    },
    components: asset.components.map((comp) => ({
      type: comp.layer === 'silicon_bsp' ? 'device' : 'library',
      name: comp.name,
      version: comp.version,
      supplier: { name: comp.supplier },
      hashes: [
        {
          alg: 'SHA-256',
          content: comp.sha256
        }
      ],
      licenses: [{ license: { id: comp.license } }],
      properties: [
        { name: 'slsa:level', value: String(comp.slsaLevel) },
        { name: 'supply_chain:tier', value: comp.tier }
      ]
    })),
    vulnerabilities: asset.vulnerabilities.map((vuln) => {
      // Map VEX status to CycloneDX 1.5 analysis state
      let state = 'in_triage';
      let justification: string | undefined = undefined;

      switch (vuln.vexStatus) {
        case 'affected_reachable':
          state = 'exploitable';
          break;
        case 'affected_not_reachable':
          state = 'not_affected';
          justification = 'vulnerable_code_not_in_execute_path';
          break;
        case 'not_affected':
          state = 'not_affected';
          justification = 'vulnerable_code_not_present';
          break;
        case 'mitigated':
          state = 'resolved';
          justification = 'inline_mitigations_exist';
          break;
      }

      return {
        id: vuln.id,
        source: {
          name: 'NVD',
          url: `https://nvd.nist.gov/vuln/detail/${vuln.id}`
        },
        ratings: [
          {
            score: vuln.cvss,
            severity: vuln.cvss >= 9.0 ? 'CRITICAL' : vuln.cvss >= 7.0 ? 'HIGH' : 'MEDIUM',
            method: 'CVSSv31'
          }
        ],
        description: vuln.name,
        analysis: {
          state: state,
          justification: justification,
          response: vuln.vexStatus === 'affected_reachable' ? ['can_not_fix', 'workaround_available'] : ['will_not_fix'],
          detail: vuln.vexJustification
        },
        affects: [
          {
            ref: `pkg:generic/${vuln.component}@${vuln.version}`
          }
        ],
        properties: [
          { name: 'epss:score', value: String(vuln.epss) },
          { name: 'cisa:kev', value: String(vuln.cisaKev) },
          { name: 'firmware:weaponizedPoc', value: String(vuln.weaponizedPoc) },
          ...(vuln.reachabilityPath ? [{ name: 'reachability:callPath', value: vuln.reachabilityPath.join(' -> ') }] : [])
        ]
      };
    })
  };

  return JSON.stringify(cycloneDxObj, null, 2);
}

/**
 * Generates an official OpenVEX JSON document
 */
export function generateOpenVex(asset: FirmwareAsset): string {
  const openVexObj = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://firmwareguard.internal/vex/${asset.id}-${Date.now()}`,
    author: 'FirmwareGuard Automated Static Reachability Engine',
    timestamp: new Date().toISOString(),
    version: 1,
    statements: asset.vulnerabilities.map((vuln) => {
      let status = 'under_investigation';
      let justification: string | undefined = undefined;

      if (vuln.vexStatus === 'affected_reachable') {
        status = 'affected';
      } else if (vuln.vexStatus === 'affected_not_reachable') {
        status = 'not_affected';
        justification = 'vulnerable_code_not_in_execute_path';
      } else if (vuln.vexStatus === 'not_affected') {
        status = 'not_affected';
        justification = 'vulnerable_code_not_present';
      } else if (vuln.vexStatus === 'mitigated') {
        status = 'fixed';
      }

      return {
        vulnerability: {
          name: vuln.id
        },
        products: [
          `pkg:firmware/${asset.manufacturer.toLowerCase().replace(/\s+/g, '-')}/${asset.model.toLowerCase()}@${asset.version}`
        ],
        status: status,
        justification: justification,
        impact_statement: vuln.clinicalImpact || vuln.gridImpact || vuln.safetyImpact || vuln.vexJustification,
        action_statement: vuln.mitigation || 'Refer to OEM security advisory for firmware patch delivery.'
      };
    })
  };

  return JSON.stringify(openVexObj, null, 2);
}
