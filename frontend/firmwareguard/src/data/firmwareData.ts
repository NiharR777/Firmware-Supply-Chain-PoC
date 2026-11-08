import { FirmwareAsset, SectorMetrics, SectorType } from '../types/firmware';

export const INITIAL_FIRMWARE_ASSETS: FirmwareAsset[] = [
  // ==========================================
  // HEALTHCARE / MEDICAL DEVICES
  // ==========================================
  {
    id: 'med-pump-rev4',
    name: 'InfusionCare Multi-Chamber Pump',
    model: 'Med-IP-400X',
    manufacturer: 'MedCare Systems Intl.',
    sector: 'healthcare',
    targetRole: 'Connected Bedside Infusion Pump',
    version: 'v2.4.1-rc3',
    releaseDate: '2024-08-14',
    architecture: 'ARM Cortex-M4',
    osType: 'FreeRTOS',
    rawCveCount: 142,
    reachableCveCount: 4,
    cisaKevCount: 1,
    signatureStatus: 'Signed & Valid',
    mttrDays: 45,
    sbomCompletenessPercent: 94,
    hardening: {
      nxDep: true,
      aslrPie: false, // MPU hardware limitation on Cortex-M4
      stackCanary: true,
      relro: 'Partial',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [
      {
        id: 'sec-med-1',
        type: 'Private RSA Key',
        location: '/firmware/keys/factory_telemetry.pem (offset 0x003180)',
        severity: 'CRITICAL',
        snippet: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA3Q9K2t5... [2048-bit Device Root Key]',
        riskDescription: 'Unencrypted private key baked into RO segment; enables remote impersonation of telemetry endpoints.'
      },
      {
        id: 'sec-med-2',
        type: 'Debug UART/JTAG Stub',
        location: 'USART2 handler (offset 0x000F4C0)',
        severity: 'HIGH',
        snippet: 'cmd_dispatch: "ENABLE_MEM_DUMP_PRIVILEGED"',
        riskDescription: 'Diagnostic engineering handler left enabled in production binary; bypasses PIN lock when UART pin is pulled high.'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2020-25111',
        name: 'Ripple20 Treck TCP/IP Critical Heap Overflow',
        component: 'treck_net_stack',
        version: 'v6.0.1.66',
        fixedVersion: 'v6.0.1.68',
        cvss: 9.8,
        epss: 0.94,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Vulnerable code path is exposed via Wi-Fi network interface handling DHCP options 119 and 252.',
        reachabilityPath: [
          'wlan0:68 (DHCP client)',
          'treck_dhcp_rx_worker()',
          'treck_parse_dns_options()',
          'tfDnsAddLabel() [Vulnerable Memcpy]'
        ],
        clinicalImpact: 'Remote unauthenticated code execution allows modification of drug library bolus rates, risking fatal overdose.',
        safetyImpact: 'Patient safety hazard (ISO 14971 Class III Device Risk)',
        mitigation: 'Quarantine Wi-Fi subnet; disable DHCP options parsing in bootloader configuration.'
      },
      {
        id: 'CVE-2022-2274',
        name: 'OpenSSL 3.0.4 RSA Bignum Remote Corruption',
        component: 'openssl',
        version: 'v3.0.4',
        fixedVersion: 'v3.0.5',
        cvss: 9.8,
        epss: 0.81,
        cisaKev: false,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Called during TLS handshake with hospital EHR central monitoring gateway.',
        reachabilityPath: [
          'ehr_ssl_connect()',
          'SSL_do_handshake()',
          'ossl_bn_rsa_x931_derive() [Vulnerable AVX-512 Bignum Path]'
        ],
        clinicalImpact: 'Allows corrupting TLS telemetry stream to falsely report normal vitals while pump is stalled.',
        mitigation: 'Enforce TLS 1.3 with ECDSA cipher suites only.'
      },
      {
        id: 'CVE-2021-3156',
        name: 'Sudo Baron Samedit Heap Overflow',
        component: 'sudo_embedded_stub',
        version: 'v1.8.31',
        cvss: 7.8,
        epss: 0.76,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_not_reachable',
        vexJustification: 'Component was bundled in SDK build tree, but the vulnerable sudo setuid binary was dead-stripped by linker.',
        mitigation: 'Compiler dead-code elimination verified via binary disassembly (radare2 call graph).'
      },
      {
        id: 'CVE-2023-38545',
        name: 'cURL SOCKS5 Heap Buffer Overflow',
        component: 'libcurl',
        version: 'v7.88.1',
        fixedVersion: 'v8.4.0',
        cvss: 9.8,
        epss: 0.88,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'not_affected',
        vexJustification: 'Config flag CURL_DISABLE_PROXY=ON was specified during BSP compilation; vulnerable SOCKS5 proxy resolver is absent.',
        mitigation: 'Verified via ELF symbol table: `curl_socks5_gssapi_negotiate` symbol is not present.'
      }
    ],
    components: [
      {
        id: 'comp-med-1',
        name: 'STM32F429 Silicon BSP',
        version: 'v1.26.2',
        layer: 'silicon_bsp',
        supplier: 'STMicroelectronics',
        tier: 'Tier 2',
        license: 'BSD-3-Clause',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'a9f14c8038b32e1850117d98342898cf871b6982980fa2a94562412e4b6c3101',
        cveCount: 12,
        reachableCveCount: 0
      },
      {
        id: 'comp-med-2',
        name: 'FreeRTOS Kernel',
        version: 'v10.4.3-LTS',
        layer: 'rtos_kernel',
        supplier: 'Amazon Web Services / FreeRTOS',
        tier: 'Tier 1',
        license: 'MIT',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '417bfa4910cfb35824987cb51a3788a531e8432314e082bf0b60cb9a545366c8',
        cveCount: 3,
        reachableCveCount: 0
      },
      {
        id: 'comp-med-3',
        name: 'Treck TCP/IP Network Stack',
        version: 'v6.0.1.66',
        layer: 'middleware',
        supplier: 'Treck Inc.',
        tier: 'Tier 1',
        license: 'Proprietary Commercial',
        slsaLevel: 1,
        hashVerified: false,
        sha256: '64d119421f5be6343588df8a764d0eb3eefb22a0756e0766348981e4bca2828b',
        cveCount: 19,
        reachableCveCount: 2
      },
      {
        id: 'comp-med-4',
        name: 'DoseDelivery Control Logic Engine',
        version: 'v2.4.1',
        layer: 'app_logic',
        supplier: 'MedCare Systems (In-House)',
        tier: 'Internal OEM',
        license: 'Proprietary',
        slsaLevel: 2,
        hashVerified: true,
        sha256: '98d578bbfa12248811d0823485cbaef81938b812066fa5a85186b51c110303ba',
        cveCount: 0,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'FDA 524B',
        status: 'Action Required',
        details: 'Section 524B(b)(1) requires complete machine-readable SBOM with verified pedigree. Treck stack lacks SLSA Level 2+ provenance.'
      },
      {
        standard: 'IEC 62443',
        status: 'Action Required',
        details: 'IEC 62443-4-2 SL-2 requirement for cryptographic key storage violated: private key stored unencrypted in flash.'
      }
    ]
  },

  {
    id: 'med-monitor-mx8',
    name: 'IntelliVitals Multi-Parameter Bedside Monitor',
    model: 'IVM-800-HL7',
    manufacturer: 'Apex Medical Corp.',
    sector: 'healthcare',
    targetRole: 'ICU Patient Monitor & DICOM Gateway',
    version: 'v3.1.8',
    releaseDate: '2024-05-19',
    architecture: 'QNX x86_64',
    osType: 'QNX Neutrino',
    rawCveCount: 98,
    reachableCveCount: 2,
    cisaKevCount: 1,
    signatureStatus: 'Signed & Valid',
    mttrDays: 32,
    sbomCompletenessPercent: 91,
    hardening: {
      nxDep: true,
      aslrPie: true,
      stackCanary: true,
      relro: 'Full',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [
      {
        id: 'sec-med-3',
        type: 'Expired X.509 Cert',
        location: '/etc/ssl/certs/dicom_node.crt (offset 0x01198A)',
        severity: 'MEDIUM',
        snippet: 'Validity: Not After: 2024-01-15 00:00:00 GMT [Expired Cert]',
        riskDescription: 'Expired DICOM peer mutual-TLS certificate triggers hospital-wide SSL certificate validation bypass flags.'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2023-44487',
        name: 'HTTP/2 Rapid Reset Denial of Service',
        component: 'nghttp2',
        version: 'v1.55.1',
        fixedVersion: 'v1.56.0',
        cvss: 7.5,
        epss: 0.89,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Active HTTP/2 web console used by central nursing station allows crashing monitor UI remotely.',
        reachabilityPath: ['eth0:443 (HTTPS Web UI)', 'http2_session_recv()', 'nghttp2_session_mem_recv()'],
        clinicalImpact: 'Nursing station loses central alarm display for cardiac arrhythmia events during rapid reset loop.',
        mitigation: 'Disable HTTP/2 support in embedded web server until patched.'
      }
    ],
    components: [
      {
        id: 'comp-med-5',
        name: 'Intel BayTrail Atom BSP',
        version: 'v2.1',
        layer: 'silicon_bsp',
        supplier: 'Intel Corp.',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'ef1284a1b023819c9918204981bc881923485718293847561829304918273645',
        cveCount: 8,
        reachableCveCount: 0
      },
      {
        id: 'comp-med-6',
        name: 'QNX Neutrino RTOS Kernel',
        version: '7.1.0',
        layer: 'rtos_kernel',
        supplier: 'BlackBerry QNX',
        tier: 'Tier 1',
        license: 'Commercial',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'c3b819a827364510293847561829304918273645a8b7c6d5e4f3a2b1c0d9e8f7',
        cveCount: 4,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'FDA 524B',
        status: 'Compliant',
        details: 'Full CycloneDX 1.5 SBOM generated with automated vulnerability disclosure protocol.'
      }
    ]
  },

  // ==========================================
  // ENERGY & UTILITIES
  // ==========================================
  {
    id: 'energy-rtu-710',
    name: 'GridDefender Protective Relay & RTU',
    model: 'GD-710-PRO',
    manufacturer: 'NorthGrid Dynamics',
    sector: 'energy',
    targetRole: 'Substation Transmission Protective Relay',
    version: 'v4.14.2',
    releaseDate: '2024-07-28',
    architecture: 'PowerPC e500',
    osType: 'VxWorks 7.0',
    rawCveCount: 189,
    reachableCveCount: 3,
    cisaKevCount: 2,
    signatureStatus: 'Signed & Valid',
    mttrDays: 68,
    sbomCompletenessPercent: 88,
    hardening: {
      nxDep: true,
      aslrPie: false,
      stackCanary: true,
      relro: 'Partial',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [
      {
        id: 'sec-nrg-1',
        type: 'Hardcoded Password',
        location: '/romfs/etc/master_dnp3.conf (offset 0x008920)',
        severity: 'HIGH',
        snippet: 'AUTH_KEY_OCTET = 0x475249445F4D41535445523230323321 ("GRID_MASTER2023!")',
        riskDescription: 'Shared default DNP3 SAv5 authentication session key embedded across entire generation batch.'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2019-12256',
        name: 'URGENT/11 VxWorks IPnet Stack Denial of Service',
        component: 'vxworks_ipnet',
        version: 'v6.9.4',
        cvss: 8.8,
        epss: 0.95,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'not_affected',
        vexJustification: 'Vendor backported proprietary zero-copy raw ethernet stack; default IPnet IGMP parser code is not compiled in.',
        gridImpact: 'Substation breaker trip prevented by stack substitution.',
        mitigation: 'Disassembly confirms IGMP parser function is pruned by build linker.'
      },
      {
        id: 'CVE-2023-34362',
        name: 'OpenSSL & DNP3 Malformed Frame Memory Corruption',
        component: 'dnp3_parser_engine',
        version: 'v3.2.1',
        fixedVersion: 'v3.2.4',
        cvss: 9.8,
        epss: 0.92,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Reachable over TCP port 20000 directly from substation SCADA wide area network.',
        reachabilityPath: [
          'eth0:20000 (DNP3 WAN interface)',
          'dnp3_listen_worker()',
          'dnp3_parse_object_header()',
          'dnp3_copy_dataset() [Out-of-Bounds Buffer Write]'
        ],
        gridImpact: 'Causes watchdog reboot loop of protective relay, leaving high-voltage transformer lines without overcurrent trip safety.',
        mitigation: 'Implement firewall rule blocking external DNP3 traffic without IPsec wrapper.'
      }
    ],
    components: [
      {
        id: 'comp-nrg-1',
        name: 'NXP QorIQ P2020 Silicon BSP',
        version: 'v1.4.0',
        layer: 'silicon_bsp',
        supplier: 'NXP Semiconductors',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '99887766554433221100aabbccddeeff112233445566778899aabbccddeeff00',
        cveCount: 15,
        reachableCveCount: 0
      },
      {
        id: 'comp-nrg-2',
        name: 'Wind River VxWorks RTOS',
        version: '7.0.2',
        layer: 'rtos_kernel',
        supplier: 'Wind River Systems',
        tier: 'Tier 1',
        license: 'Commercial',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef',
        cveCount: 22,
        reachableCveCount: 0
      },
      {
        id: 'comp-nrg-3',
        name: 'OpenDNP3 Protocol Stack',
        version: 'v3.2.1',
        layer: 'middleware',
        supplier: 'Automatiq Open Source',
        tier: 'Tier 1',
        license: 'Apache-2.0',
        slsaLevel: 2,
        hashVerified: true,
        sha256: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
        cveCount: 8,
        reachableCveCount: 1
      }
    ],
    complianceGaps: [
      {
        standard: 'NERC CIP-013-1',
        status: 'Action Required',
        details: 'Requirement R1.2: Missing hardware root-of-trust attestation for Tier-2 silicon supplier components.'
      },
      {
        standard: 'IEC 62443',
        status: 'Action Required',
        details: 'IEC 62443-3-3 System Security Requirements: Default session key in flash breaches authentication partition.'
      }
    ]
  },

  {
    id: 'energy-meter-smart',
    name: 'SynchroGrid Advanced AMI Smart Meter',
    model: 'AMI-Sync-900',
    manufacturer: 'VoltSync Infrastructure',
    sector: 'energy',
    targetRole: 'Residential & Commercial Smart Energy Meter',
    version: 'v1.9.0',
    releaseDate: '2024-03-10',
    architecture: 'Renesas RX65N',
    osType: 'FreeRTOS',
    rawCveCount: 74,
    reachableCveCount: 1,
    cisaKevCount: 0,
    signatureStatus: 'Signed & Valid',
    mttrDays: 52,
    sbomCompletenessPercent: 82,
    hardening: {
      nxDep: true,
      aslrPie: false,
      stackCanary: true,
      relro: 'None',
      fortifySource: false,
      strippedSymbols: true,
    },
    secrets: [],
    vulnerabilities: [
      {
        id: 'CVE-2020-13987',
        name: 'lwIP TCP/IP Stack Memory Poisoning',
        component: 'lwip',
        version: 'v2.1.1',
        fixedVersion: 'v2.1.3',
        cvss: 7.5,
        epss: 0.65,
        cisaKev: false,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Exposed via Zigbee/Cellular mesh network gateway interface.',
        reachabilityPath: ['mesh0:53 (mDNS/DNS)', 'lwip_dns_recv()', 'lwip_parse_rr()'],
        gridImpact: 'Allows mass remote disconnection of residential smart meters causing artificial demand surge.',
        mitigation: 'Update to lwIP 2.1.3 via signed delta OTA.'
      }
    ],
    components: [
      {
        id: 'comp-nrg-4',
        name: 'Renesas RX65N Hardware BSP',
        version: 'v1.12',
        layer: 'silicon_bsp',
        supplier: 'Renesas Electronics',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
        cveCount: 5,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'NERC CIP-013-1',
        status: 'Compliant',
        details: 'All component vendors submitted third-party software attestation and vulnerability disclosure commitments.'
      }
    ]
  },

  // ==========================================
  // OIL & GAS
  // ==========================================
  {
    id: 'oil-sis-3008',
    name: 'TricoSafe SIS Safety Instrumented Controller',
    model: 'SIS-MP3008-TriStation',
    manufacturer: 'AeroPetro Automation',
    sector: 'oil_gas',
    targetRole: 'Refinery Emergency Shutdown (ESD) Safety Controller',
    version: 'v10.4.1-b2',
    releaseDate: '2024-09-02',
    architecture: 'ARM Cortex-R5',
    osType: 'Bare-metal',
    rawCveCount: 88,
    reachableCveCount: 2,
    cisaKevCount: 2,
    signatureStatus: 'Deprecated MD5',
    mttrDays: 82,
    sbomCompletenessPercent: 79,
    hardening: {
      nxDep: false, // Legacy safety lockstep execution allows RAM execution
      aslrPie: false,
      stackCanary: false, // Disabled due to hard real-time jitter requirements
      relro: 'None',
      fortifySource: false,
      strippedSymbols: false, // Debug symbol table retained for safety certification
    },
    secrets: [
      {
        id: 'sec-oil-1',
        type: 'Hardcoded Password',
        location: '/flash/boot/diag_creds.bin (offset 0x00014B2)',
        severity: 'CRITICAL',
        snippet: 'MAGIC_KEY = "TRIC_ENG_MODE_BYPASS_#992"',
        riskDescription: 'Undocumented diagnostic bypass key allows modifying safety state while key switch is in RUN position (TRITON/HatMan attack vector).'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2017-6016',
        name: 'TriStation Protocol Arbitrary Memory Write (TRITON Target)',
        component: 'tristation_debug_proto',
        version: 'v4.2',
        cvss: 9.8,
        epss: 0.98,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Reachable over maintenance Ethernet port (UDP port 1502). Enables injecting malicious backdoor code into SIS RAM.',
        reachabilityPath: [
          'eth1:1502 (TriStation Maintenance Port)',
          'ts_recv_packet()',
          'ts_cmd_execute_0x1A()',
          'write_ram_buffer() [Arbitrary Memory Injection]'
        ],
        safetyImpact: 'Disables automatic emergency shutdown systems during toxic gas / pressure surge conditions, risking refinery explosion.',
        mitigation: 'Physically lock controller key switch to RUN and implement uni-directional data diode on maintenance port.'
      },
      {
        id: 'CVE-2022-45139',
        name: 'Modbus-TCP Length Field Integer Wrap',
        component: 'modbus_slave_engine',
        version: 'v2.1.0',
        fixedVersion: 'v2.1.4',
        cvss: 7.5,
        epss: 0.72,
        cisaKev: true,
        weaponizedPoc: false,
        vexStatus: 'mitigated',
        vexJustification: 'Compensating control active: Hardware firewall / DPI filter inspects and drops malformed Modbus packets before reach.',
        safetyImpact: 'Mitigated by plant industrial perimeter firewall.',
        mitigation: 'Keep DPI filter rule set active on Moxa gateway.'
      }
    ],
    components: [
      {
        id: 'comp-oil-1',
        name: 'TI Hercules TMS570 Dual-Core Lockstep BSP',
        version: 'v2.8',
        layer: 'silicon_bsp',
        supplier: 'Texas Instruments',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '1122334455667788990011223344556677889900112233445566778899001122',
        cveCount: 2,
        reachableCveCount: 0
      },
      {
        id: 'comp-oil-2',
        name: 'TriStation Communication Middleware',
        version: 'v4.2.0',
        layer: 'middleware',
        supplier: 'Legacy OEM Invensys Component',
        tier: 'Tier 1',
        license: 'Proprietary',
        slsaLevel: 0,
        hashVerified: false,
        sha256: '9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef',
        cveCount: 14,
        reachableCveCount: 1
      }
    ],
    complianceGaps: [
      {
        standard: 'TSA Pipeline Directives',
        status: 'Non-Compliant',
        details: 'TSA SD Pipeline-2021-02C requires cryptographic signature validation for all firmware components. MD5 checksum is deprecated.'
      },
      {
        standard: 'IEC 62443',
        status: 'Action Required',
        details: 'IEC 62443-4-1 Secure Product Development: Unstripped debug symbols and hardcoded diagnostic bypass present in release firmware.'
      }
    ]
  },

  {
    id: 'oil-rtu-roc809',
    name: 'HydroFlow Wellhead & Pipeline RTU',
    model: 'HF-ROC-809',
    manufacturer: 'HydroDynamics PetroTech',
    sector: 'oil_gas',
    targetRole: 'Remote Gathering & Custody Transfer Flow Computer',
    version: 'v2.7.3',
    releaseDate: '2024-04-22',
    architecture: 'Embedded Linux ARM64',
    osType: 'Embedded Linux (Yocto)',
    rawCveCount: 165,
    reachableCveCount: 3,
    cisaKevCount: 1,
    signatureStatus: 'Signed & Valid',
    mttrDays: 59,
    sbomCompletenessPercent: 86,
    hardening: {
      nxDep: true,
      aslrPie: true,
      stackCanary: true,
      relro: 'Partial',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [
      {
        id: 'sec-oil-2',
        type: 'AWS / Cloud Token',
        location: '/etc/telemetry/cloud_iot.json (offset 0x00452E)',
        severity: 'HIGH',
        snippet: 'AWS_ACCESS_KEY_ID = "AKIA5EXAMPLEPIPELINE7"',
        riskDescription: 'Staging AWS credentials found in firmware image; allows reading pipeline flow rates and valve positions.'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2021-44228',
        name: 'Log4Shell JNDI Remote Code Execution',
        component: 'apache_log4j_embedded',
        version: 'v2.14.1',
        fixedVersion: 'v2.17.1',
        cvss: 10.0,
        epss: 0.97,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Java web gateway for technician calibration logs HTTP headers via vulnerable Log4j.',
        reachabilityPath: ['eth0:8080 (REST API)', 'DiagnosticServlet.doPost()', 'logger.info(User-Agent)'],
        safetyImpact: 'Allows takeover of flow computer, enabling manipulation of pressure relief valve thresholds.',
        mitigation: 'Set -Dlog4j2.formatMsgNoLookups=true in JVM options or upgrade to log4j 2.17.1.'
      }
    ],
    components: [
      {
        id: 'comp-oil-3',
        name: 'NXP i.MX8M Application Processor BSP',
        version: 'v5.10.72',
        layer: 'silicon_bsp',
        supplier: 'NXP Semiconductors',
        tier: 'Tier 2',
        license: 'GPL-2.0',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '3344556677889900112233445566778899001122334455667788990011223344',
        cveCount: 28,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'TSA Pipeline Directives',
        status: 'Action Required',
        details: 'TSA directive requires 48-hour reporting and mitigation plan for CISA KEV vulnerabilities in operational technology.'
      }
    ]
  },

  // ==========================================
  // AUTOMOTIVE SECTOR
  // ==========================================
  {
    id: 'auto-ecu-gateway',
    name: 'AeroDrive Central Gateway & ADAS ECU',
    model: 'CGW-ADAS-5000',
    manufacturer: 'Apex Mobility Electronics',
    sector: 'automotive',
    targetRole: 'Vehicle Central Gateway & Level 2+ ADAS Domain Controller',
    version: 'v5.2.0-hotfix2',
    releaseDate: '2024-09-18',
    architecture: 'TriCore TC397',
    osType: 'AUTOSAR Classic',
    rawCveCount: 112,
    reachableCveCount: 2,
    cisaKevCount: 1,
    signatureStatus: 'Signed & Valid',
    mttrDays: 38,
    sbomCompletenessPercent: 96,
    hardening: {
      nxDep: true,
      aslrPie: true,
      stackCanary: true,
      relro: 'Full',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [
      {
        id: 'sec-auto-1',
        type: 'Private RSA Key',
        location: '/sec_store/ota_staging_sig.pem (offset 0x00FE20)',
        severity: 'CRITICAL',
        snippet: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk... [OTA Staging Key]',
        riskDescription: 'Tier-1 supplier left internal test OTA signing private key in production build; allows forging diagnostic updates.'
      }
    ],
    vulnerabilities: [
      {
        id: 'CVE-2021-35937',
        name: 'AUTOSAR Diagnostic Stack UDS Buffer Overflow',
        component: 'autosar_dcm_stack',
        version: 'v4.4.0',
        fixedVersion: 'v4.4.2',
        cvss: 8.8,
        epss: 0.84,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Reachable via OBD-II port or Automotive Ethernet (DoIP port 13400) diagnostic service $27 (Security Access).',
        reachabilityPath: [
          'doip0:13400 (DoIP Diagnostic Interface)',
          'DoIP_ProcessMessage()',
          'Dcm_ProcessSecurityAccess()',
          'Dcm_ValidateSeedKey() [Heap Overflow]'
        ],
        safetyImpact: 'Enables pivot from infotainment/diagnostics domain to safety-critical powertrain CAN-bus (steering/braking control).',
        mitigation: 'Disable DoIP external routing during vehicle motion (speed > 0 km/h).'
      },
      {
        id: 'CVE-2023-38545',
        name: 'cURL SOCKS5 Heap Buffer Overflow in OTA Agent',
        component: 'libcurl',
        version: 'v7.88.1',
        cvss: 9.8,
        epss: 0.88,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_not_reachable',
        vexJustification: 'cURL is statically linked in the OTA client daemon, but proxy configuration is hardcoded to DIRECT connection only.',
        safetyImpact: 'No impact under current production network topology.',
        mitigation: 'Dead code verified; will be upgraded to 8.4.0 in next scheduled quarterly flash cycle.'
      }
    ],
    components: [
      {
        id: 'comp-auto-1',
        name: 'Infineon AURIX TC397XX Microcontroller BSP',
        version: 'v3.2',
        layer: 'silicon_bsp',
        supplier: 'Infineon Technologies',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
        cveCount: 6,
        reachableCveCount: 0
      },
      {
        id: 'comp-auto-2',
        name: 'Vector AUTOSAR Classic BSW Stack',
        version: 'v4.4.0',
        layer: 'rtos_kernel',
        supplier: 'Vector Informatik GmbH',
        tier: 'Tier 1',
        license: 'Proprietary Commercial',
        slsaLevel: 3,
        hashVerified: true,
        sha256: '77889900aabbccddeeff00112233445566778899aabbccddeeff001122334455',
        cveCount: 11,
        reachableCveCount: 1
      },
      {
        id: 'comp-auto-3',
        name: 'SOME/IP & DoIP Routing Daemon',
        version: 'v2.1.4',
        layer: 'middleware',
        supplier: 'Apex Mobility (In-House)',
        tier: 'Internal OEM',
        license: 'Proprietary',
        slsaLevel: 2,
        hashVerified: true,
        sha256: '8899001122334455667788990011223344556677889900112233445566778899',
        cveCount: 4,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'UNECE R155/R156',
        status: 'Action Required',
        details: 'UNECE R155 clause 7.2 requires Tier-1 and Tier-2 supply chain risk mitigation for unauthorized OTA signing keys found in binary.'
      },
      {
        standard: 'IEC 62443',
        status: 'Compliant',
        details: 'Full hardware security module (HSM/SHE) secure boot chain attested.'
      }
    ]
  },

  {
    id: 'auto-tcu-5g',
    name: 'Veloce Connect 5G Telematics Control Unit',
    model: 'TCU-5G-V2X',
    manufacturer: 'Veloce Automotive Electronics',
    sector: 'automotive',
    targetRole: 'Cellular 5G, C-V2X & Bluetooth Remote Gateway',
    version: 'v3.8.4',
    releaseDate: '2024-06-11',
    architecture: 'Embedded Linux ARM64',
    osType: 'Embedded Linux (Yocto)',
    rawCveCount: 154,
    reachableCveCount: 3,
    cisaKevCount: 2,
    signatureStatus: 'Signed & Valid',
    mttrDays: 41,
    sbomCompletenessPercent: 92,
    hardening: {
      nxDep: true,
      aslrPie: true,
      stackCanary: true,
      relro: 'Full',
      fortifySource: true,
      strippedSymbols: true,
    },
    secrets: [],
    vulnerabilities: [
      {
        id: 'CVE-2020-12351',
        name: 'BleedingTooth Linux Bluetooth L2CAP Zero-Click RCE',
        component: 'bluez_stack',
        version: 'v5.50',
        fixedVersion: 'v5.55',
        cvss: 9.8,
        epss: 0.96,
        cisaKev: true,
        weaponizedPoc: true,
        vexStatus: 'affected_reachable',
        vexJustification: 'Bluetooth controller accepts L2CAP connection requests without requiring user pairing (zero-click proximate attack).',
        reachabilityPath: [
          'hci0 (Bluetooth Controller)',
          'l2cap_connect_req()',
          'l2cap_le_sig_cmd()',
          'a2mp_channel_create() [Out-of-Bounds Memory Write]'
        ],
        safetyImpact: 'Proximate attacker (within 30m of vehicle) can achieve root code execution on TCU and pivot to vehicle telematics CAN-bus.',
        mitigation: 'Disable non-paired Bluetooth visibility and apply upstream BlueZ 5.55 kernel backport patch.'
      }
    ],
    components: [
      {
        id: 'comp-auto-4',
        name: 'Qualcomm Snapdragon Automotive 5G Platform',
        version: 'v4.2.1',
        layer: 'silicon_bsp',
        supplier: 'Qualcomm Inc.',
        tier: 'Tier 2',
        license: 'Proprietary',
        slsaLevel: 3,
        hashVerified: true,
        sha256: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
        cveCount: 18,
        reachableCveCount: 0
      }
    ],
    complianceGaps: [
      {
        standard: 'UNECE R155/R156',
        status: 'Action Required',
        details: 'Requires OTA software update management system (SUMS) patch delivery within 14 days of weaponized zero-click disclosure.'
      }
    ]
  }
];

export const SECTOR_METRICS_DATA: Record<SectorType, SectorMetrics> = {
  energy: {
    sector: 'energy',
    title: 'Energy & Electric Grid',
    totalAssets: 48,
    totalComponents: 812,
    rawCves: 263,
    reachableCves: 4,
    activeKevCount: 2,
    unsignedCount: 0,
    secretsCount: 1,
    avgSbomScore: 85,
    primaryStandard: 'NERC CIP-013-1 / IEC 61850',
    riskScore: 84
  },
  oil_gas: {
    sector: 'oil_gas',
    title: 'Oil & Gas / Petrochemical',
    totalAssets: 34,
    totalComponents: 590,
    rawCves: 253,
    reachableCves: 5,
    activeKevCount: 3,
    unsignedCount: 1,
    secretsCount: 2,
    avgSbomScore: 82,
    primaryStandard: 'TSA SD Pipeline / IEC 62443',
    riskScore: 91
  },
  healthcare: {
    sector: 'healthcare',
    title: 'Healthcare & Medical Devices',
    totalAssets: 62,
    totalComponents: 1140,
    rawCves: 240,
    reachableCves: 6,
    activeKevCount: 2,
    unsignedCount: 0,
    secretsCount: 3,
    avgSbomScore: 93,
    primaryStandard: 'FDA Section 524B / ISO 14971',
    riskScore: 78
  },
  automotive: {
    sector: 'automotive',
    title: 'Automotive & Connected Fleets',
    totalAssets: 56,
    totalComponents: 980,
    rawCves: 266,
    reachableCves: 5,
    activeKevCount: 3,
    unsignedCount: 0,
    secretsCount: 1,
    avgSbomScore: 94,
    primaryStandard: 'UNECE WP.29 R155/R156 / ISO 21434',
    riskScore: 65
  }
};
