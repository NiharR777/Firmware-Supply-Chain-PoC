
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateCycloneDxDocument,
  validateOpenVexDocument
} from './vexSchemaValidator';

describe('CycloneDX 1.5 production schema validator', () => {
  it('accepts a valid CycloneDX BOM', () => {
    const document = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:123e4567-e89b-12d3-a456-426614174000',
      version: 1,
      metadata: {
        timestamp: '2026-11-21T00:00:00Z',
        tools: []
      },
      components: []
    };

    const result = validateCycloneDxDocument(document);

    assert.equal(result.valid, true, result.errors.join('; '));
    assert.equal(result.format, 'CycloneDX 1.5');
    assert.deepEqual(result.errors, []);
  });

  it('rejects a document with an invalid BOM format', () => {
    const result = validateCycloneDxDocument({
      bomFormat: 'InvalidFormat',
      specVersion: '1.5',
      version: 1
    });

    assert.equal(result.valid, false);
    assert.equal(result.format, 'CycloneDX 1.5');
    assert.ok(result.errors.length > 0);
  });

  it('returns useful errors for a missing required field', () => {
    const result = validateCycloneDxDocument({
      bomFormat: 'CycloneDX'
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
    assert.ok(result.errors.some((error) => error.includes('required')));
  });
});

describe('OpenVEX 0.2.0 production schema validator', () => {
  it('accepts a valid OpenVEX document', () => {
    const document = {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'urn:uuid:123e4567-e89b-12d3-a456-426614174000',
      author: 'FirmwareGuard',
      timestamp: '2026-11-21T00:00:00Z',
      version: 1,
      statements: [
        {
          vulnerability: {
            '@id': 'https://www.cve.org/CVERecord?id=CVE-2024-12345',
            name: 'Test vulnerability'
          },
          products: [
            {
              '@id': 'https://example.com/products/test-library/1.0.0'
            }
          ],
          status: 'affected',
          action_statement: 'A security update is required.'
        }
      ]
    };

    const result = validateOpenVexDocument(document);

    assert.equal(
      result.valid,
      true,
      `OpenVEX validation errors: ${result.errors.join('; ')}`
    );
    assert.equal(result.format, 'OpenVEX 0.2.0');
    assert.deepEqual(result.errors, []);
  });

  it('rejects an invalid OpenVEX document', () => {
    const result = validateOpenVexDocument({
      '@context': 'invalid-context',
      version: 1,
      statements: []
    });

    assert.equal(result.valid, false);
    assert.equal(result.format, 'OpenVEX 0.2.0');
    assert.ok(result.errors.length > 0);
  });

  it('rejects a document that is not an object', () => {
    const result = validateOpenVexDocument(null);

    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });
});
