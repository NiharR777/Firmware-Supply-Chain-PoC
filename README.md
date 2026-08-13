# Firmware & Supply-Chain Assurance PoC

## About the Project

This project is a proof of concept for checking the security and trustworthiness of firmware and software packages.

The main idea is to check whether a package is genuine, properly signed, contains the expected software components, and has any known security or supply-chain issues.

The project uses synthetic data, so no real firmware or production system is affected.

## What the Project Checks

The system will check:

- Package integrity
- SHA-256 hash
- Signature and attestation
- SBOM information
- Vulnerabilities and VEX information
- Vendor and provenance details
- Package version and rollback issues
- Unexpected component changes
- Dependency impact
- Unusual package or release behaviour

## Decision

After checking the available evidence, the system will give one of these recommendations:

- Accept
- Investigate
- High Risk

The recommendation is only for review. A human must approve any action.

## Safety

This project is completely read-only and uses synthetic evidence.

It will not:

- Flash firmware
- Install software
- Delete files
- Automatically quarantine packages
- Modify real devices
- Modify production systems
- Execute destructive actions

## Machine Learning

Machine learning will be used only to identify unusual behaviour and help rank the risk.

It will not override important deterministic checks such as an invalid hash or signature.

## Current Status

Sprint 0 - Project setup and scope definition

Status: In Progress