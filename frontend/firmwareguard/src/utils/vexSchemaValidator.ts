
import Ajv from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import addDraft2019Formats from 'ajv-formats-draft2019';

import cycloneDxSchema from '../../schemas/cyclonedx-bom-1.5.schema.json';
import jsfSchema from '../../schemas/jsf-0.82.schema.json';
import openVexSchema from '../../schemas/openvex-0.2.0.schema.json';
import spdxSchema from '../../schemas/spdx.schema.json';

export interface SchemaValidationResult {
  valid: boolean;
  format: 'CycloneDX 1.5' | 'OpenVEX 0.2.0';
  errors: string[];
}

type ValidationError = {
  instancePath: string;
  message?: string;
};

function formatErrors(
  errors: ValidationError[] | null | undefined
): string[] {
  if (!errors) {
    return [];
  }

  return errors.map((error) => {
    const location = error.instancePath || '/';
    const message = error.message || 'Schema validation failed';

    return `${location}: ${message}`;
  });
}

// --------------------------------------------------
// CycloneDX 1.5 — JSON Schema Draft-07
// --------------------------------------------------

const draft7Ajv = new Ajv({
  allErrors: true,
  strict: false
});

addFormats(draft7Ajv);
addDraft2019Formats(draft7Ajv);

// Register external schema dependencies.
draft7Ajv.addSchema(jsfSchema);
draft7Ajv.addSchema(spdxSchema);

const validateCycloneDx = draft7Ajv.compile(cycloneDxSchema);

// --------------------------------------------------
// OpenVEX 0.2.0 — JSON Schema 2020-12
// --------------------------------------------------

const draft2020Ajv = new Ajv2020({
  allErrors: true,
  strict: false
});

addFormats(draft2020Ajv);
addDraft2019Formats(draft2020Ajv);

const validateOpenVex = draft2020Ajv.compile(openVexSchema);

// --------------------------------------------------
// Public validation functions
// --------------------------------------------------

export function validateCycloneDxDocument(
  document: unknown
): SchemaValidationResult {
  const valid = validateCycloneDx(document);

  return {
    valid: Boolean(valid),
    format: 'CycloneDX 1.5',
    errors: valid ? [] : formatErrors(validateCycloneDx.errors)
  };
}

export function validateOpenVexDocument(
  document: unknown
): SchemaValidationResult {
  const valid = validateOpenVex(document);

  return {
    valid: Boolean(valid),
    format: 'OpenVEX 0.2.0',
    errors: valid ? [] : formatErrors(validateOpenVex.errors)
  };
}
