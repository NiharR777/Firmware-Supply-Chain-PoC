"""Offline ML input checks. No policy fusion or deployment action is performed.

The correction profile is built from training FEATURES only. Its min/max envelope
and observed discrete combinations are conservative review controls, not a tuned
or validated general OOD detector. Experiment v1 remains rejected.
"""
from __future__ import annotations

import math
from numbers import Real

FEATURES = (
    'hash_mismatch', 'signature_invalid', 'trusted_root_invalid', 'vendor_mismatch',
    'vendor_untrusted', 'sbom_missing', 'sbom_incomplete', 'version_changed',
    'version_major_delta', 'unauthorized_rollback', 'vulnerability_present',
    'vulnerability_applicable', 'unexpected_component', 'evidence_age_days',
    'stale_evidence', 'package_size_mb', 'component_count', 'component_count_delta',
    'known_vulnerability_count', 'max_cvss_score', 'hard_failure_count',
    'evidence_issue_count',
)
BINARY = tuple(f for f in FEATURES if f not in {
    'version_major_delta', 'evidence_age_days', 'package_size_mb', 'component_count',
    'component_count_delta', 'known_vulnerability_count', 'max_cvss_score',
    'hard_failure_count', 'evidence_issue_count',
})
INTEGER = set(FEATURES) - {'package_size_mb', 'max_cvss_score'}
SIGNED = {'version_major_delta', 'component_count_delta'}
HARD = ('hash_mismatch', 'signature_invalid', 'trusted_root_invalid', 'vendor_untrusted', 'unauthorized_rollback')
ISSUES = ('sbom_missing', 'sbom_incomplete', 'stale_evidence')

def signature(row):
    return ','.join(str(int(row[f])) for f in BINARY)

def schema_reasons(row):
    if not isinstance(row, dict):
        return ['input_must_be_a_mapping']
    if set(row) != set(FEATURES):
        return ['feature_schema_mismatch']
    reasons = []
    for name in FEATURES:
        value = row[name]
        if not isinstance(value, Real) or not math.isfinite(value):
            reasons.append(f'invalid_numeric:{name}')
        elif name in BINARY and value not in (0, 1):
            reasons.append(f'invalid_boolean:{name}')
        elif name in INTEGER and value != int(value):
            reasons.append(f'noninteger:{name}')
        elif name not in SIGNED and value < 0:
            reasons.append(f'negative:{name}')
    if reasons:
        return reasons
    if row['max_cvss_score'] > 10:
        reasons.append('cvss_out_of_range')
    if row['package_size_mb'] <= 0:
        reasons.append('nonpositive_package_size')
    if row['hard_failure_count'] != sum(row[f] for f in HARD):
        reasons.append('contradictory_hard_failure_count')
    if row['evidence_issue_count'] != sum(row[f] for f in ISSUES):
        reasons.append('contradictory_evidence_issue_count')
    if not row['version_changed'] and (row['version_major_delta'] or row['unauthorized_rollback']):
        reasons.append('contradictory_version_evidence')
    # Other apparently conflicting fields (e.g. vendor mismatch with a trusted
    # vendor) can be valid evidence and must not be rewritten by this guard.
    return reasons

def build_profile(training_rows, training_record_ids):
    rows = list(training_rows)
    ids = list(training_record_ids)
    if not rows or len(rows) != len(ids) or len(set(ids)) != len(ids):
        raise ValueError('Training records must be nonempty, unique and aligned')
    if any(schema_reasons(row) for row in rows):
        raise ValueError('Invalid training feature schema')
    return {
        'version': 'correction-20260912-v1', 'fit_split': 'train',
        'fit_record_ids': ids, 'features': list(FEATURES),
        'range_rule': 'inclusive_training_min_max',
        'bounds': {f: [min(r[f] for r in rows), max(r[f] for r in rows)] for f in FEATURES},
        'binary_combinations': sorted({signature(row) for row in rows}),
        'limitations': 'Conservative envelope; cannot detect all OOD inputs; future protocol approval required.',
    }

def inspect_features(row, profile):
    reasons = schema_reasons(row)
    if not reasons:
        if profile.get('features') != list(FEATURES) or profile.get('fit_split') != 'train':
            reasons = ['invalid_profile']
        else:
            for feature in FEATURES:
                bounds = profile.get('bounds', {}).get(feature)
                if not isinstance(bounds, list) or len(bounds) != 2 or any(not isinstance(v, Real) or not math.isfinite(v) for v in bounds) or bounds[0] > bounds[1]:
                    reasons.append(f'invalid_profile_bounds:{feature}')
                elif not bounds[0] <= row[feature] <= bounds[1]:
                    reasons.append(f'outside_training_envelope:{feature}')
            if signature(row) not in profile.get('binary_combinations', []):
                reasons.append('unseen_binary_combination')
    return {'status': 'ABSTAIN' if reasons else 'INPUT_VALID',
            'review_route': 'investigate' if reasons else None,
            'ml_score': None, 'reasons': reasons}

def assess_for_review(row, profile, *, experiment_status='REJECTED'):
    """Read-only eligibility result; never invokes a model or changes policy."""
    result = inspect_features(row, profile)
    if experiment_status != 'ACCEPTED':
        result['status'] = 'ABSTAIN'
        result['review_route'] = 'investigate'
        result['reasons'].append('experiment_not_accepted')
    return result
