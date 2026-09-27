"""Post-hoc inspection of CLOSED Experiment v1. Never fit, select or tune a model.

Only load the supplied model after its historical manifest hash has been checked.
Joblib files execute Python when loaded; use this on the reviewed package only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import platform
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.supply_chain.ml_input_guard import FEATURES, BINARY, build_profile, inspect_features, assess_for_review

DATA = ROOT / 'data/synthetic/supply_chain_poc/dataset'
OLD = ROOT / 'artifacts/ml_experiment'
CLASSES = ['normal', 'investigate', 'high_risk']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8', newline='\n')

def read_csv(path):
    with path.open(encoding='utf-8', newline='') as handle:
        return list(csv.DictReader(handle))

def historical_integrity():
    manifest = read_json(OLD / 'experiment_manifest.json')
    checks = []
    for key, mapping in manifest.items():
        if not isinstance(mapping, dict):
            continue
        for name, expected in mapping.items():
            if isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected):
                path = ROOT / name.replace('\\', '/')
                checks.append({'path': path.relative_to(ROOT).as_posix(), 'pass': path.is_file() and digest(path) == expected})
    assert len(checks) == 19 and all(c['pass'] for c in checks), checks
    dataset_checks = read_json(DATA / 'dataset_file_hashes.json')
    assert all(digest(DATA / n) == h for n, h in dataset_checks.items())
    assert manifest['status'] == 'REJECTED'
    return {'historical_hashes': checks, 'dataset_hash_count': len(dataset_checks), 'all_pass': True}

def rate(numerator, denominator):
    return numerator / denominator if denominator else None

def classification_counts(rows):
    per_class = {}
    for label in CLASSES:
        tp = sum(r['ground_truth_label'] == label and r['predicted_label'] == label for r in rows)
        fn = sum(r['ground_truth_label'] == label and r['predicted_label'] != label for r in rows)
        fp = sum(r['ground_truth_label'] != label and r['predicted_label'] == label for r in rows)
        tn = len(rows) - tp - fn - fp
        per_class[label] = {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn, 'recall': rate(tp, tp + fn),
                            'fpr': rate(fp, fp + tn), 'fnr': rate(fn, tp + fn),
                            'precision': rate(tp, tp + fp), 'f1': rate(2 * tp, 2 * tp + fp + fn)}
    return {'count': len(rows), 'class_counts': dict(Counter(r['ground_truth_label'] for r in rows)),
            'accuracy': rate(sum(r['ground_truth_label'] == r['predicted_label'] for r in rows), len(rows)),
            'per_class': per_class}

def subgroup_report(predictions, observed, features):
    overall = classification_counts(predictions)
    groups = []
    def add(kind, value, rows):
        metrics = classification_counts(rows)
        hr = metrics['per_class']['high_risk']
        base = overall['per_class']['high_risk']
        gaps = {k: None if hr[k] is None else hr[k] - base[k] for k in ['recall', 'fpr', 'fnr']}
        eligible = len(rows) >= 30
        checks = {k: 'NOT_ESTIMABLE' if gaps[k] is None else ('PASS' if abs(gaps[k]) <= .10 else 'FAIL') for k in ['recall', 'fpr']}
        status = ('DESCRIPTIVE_ONLY' if not eligible else 'FAIL' if 'FAIL' in checks.values()
                  else 'PARTIAL_NOT_ESTIMABLE' if 'NOT_ESTIMABLE' in checks.values() else 'PASS')
        groups.append({'dimension': kind, 'group': str(value), **metrics, 'high_risk_gaps_vs_overall': gaps,
                       'eligible_n_ge_30': eligible, 'gate_checks': checks, 'status': status,
                       'remediation': 'Need independent labelled coverage of absent classes before operational claims.' if status == 'PARTIAL_NOT_ESTIMABLE' else 'None for this descriptive synthetic audit.'})
    for column in ['observed_vendor_id', 'product_id', 'lineage_id']:
        for value in sorted({observed[r['record_id']][column] for r in predictions}):
            add(column, value, [r for r in predictions if observed[r['record_id']][column] == value])
    for feature in BINARY:
        for value in [0, 1]:
            add('evidence_category', f'{feature}={value}', [r for r in predictions if features[r['record_id']][feature] == value])
    return {'kind': 'POST_HOC_FROZEN_PREDICTION_AUDIT', 'definition': 'One-vs-rest per class; acceptance gaps use high_risk versus all other labels. Undefined denominators remain null, never zero.',
            'minimum_group_size': 30, 'absolute_gap_limit': .10, 'overall': overall, 'groups': groups,
            'gate_failure_count': sum(g['status'] == 'FAIL' for g in groups),
            'not_estimable_group_count': sum(g['status'] == 'PARTIAL_NOT_ESTIMABLE' for g in groups),
            'limitation': 'Synthetic technical groups, not demographic fairness or real vendor-performance evidence.'}

def probability_report(predictions):
    probs = [[float(r['prob_' + c]) for c in CLASSES] for r in predictions]
    assert all(all(math.isfinite(v) and 0 <= v <= 1 for v in p) and abs(sum(p) - 1) < 1e-9 for p in probs)
    logloss = sum(-math.log(max(p[CLASSES.index(r['ground_truth_label'])], 1e-15)) for r,p in zip(predictions, probs)) / len(probs)
    brier = sum(sum((v - int(c == r['ground_truth_label'])) ** 2 for c,v in zip(CLASSES,p)) for r,p in zip(predictions,probs)) / len(probs)
    bins = []
    for i in range(10):
        pairs = [(r,p) for r,p in zip(predictions,probs) if min(int(max(p)*10),9) == i]
        bins.append({'bin':i, 'count':len(pairs), 'confidence':sum(max(p) for r,p in pairs)/len(pairs) if pairs else None,
                     'accuracy':sum(CLASSES[max(range(3), key=lambda j:p[j])] == r['ground_truth_label'] for r,p in pairs)/len(pairs) if pairs else None})
    ece = sum(b['count']/len(probs)*abs(b['confidence']-b['accuracy']) for b in bins if b['count'])
    return {'source': 'Existing frozen prediction CSV; no refitting or threshold change', 'log_loss':logloss, 'multiclass_brier_sum_over_classes':brier,
            'ece_10_fixed_bins':ece, 'reliability_bins':bins, 'gates': {'log_loss':logloss <= .25, 'brier':brier <= .1, 'ece':ece <= .05}}

def robustness_report(profile, train_rows):
    import random
    rng = random.Random(20260903)
    base = dict(train_rows[0])
    cases = []
    def check(name, row, expect_abstain):
        result = inspect_features(row, profile)
        expected = 'ABSTAIN' if expect_abstain else 'INPUT_VALID'
        assert result['status'] == expected, (name, result)
        assert result['ml_score'] is None
        if expect_abstain:
            assert result['review_route'] == 'investigate'
        cases.append({'case':name, 'expected':expected, 'result':result, 'pass':True})
    check('valid_training_record', base, False)
    check('nonmapping', [], True)
    for feature in FEATURES:
        row = dict(base); del row[feature]
        check('missing:' + feature, row, True)
        for label, value in [('null',None), ('string','1'), ('nan',float('nan')), ('pos_inf',float('inf')), ('neg_inf',float('-inf'))]:
            row = dict(base); row[feature] = value
            check(label + ':' + feature, row, True)
    row = dict(base); row['expected_decision'] = 'normal'; check('forbidden_extra_label', row, True)
    row = dict(base); row['hash_mismatch'] = 2; check('invalid_boolean', row, True)
    row = dict(base); row['component_count'] = .5; check('fractional_component_count', row, True)
    row = dict(base); row['max_cvss_score'] = 11; check('cvss_range', row, True)
    row = dict(base); row['evidence_age_days'] = -1; check('negative_age', row, True)
    row = dict(base); row['hard_failure_count'] += 1; check('contradictory_aggregate', row, True)
    row = dict(base); row['package_size_mb'] = profile['bounds']['package_size_mb'][1] + 1000; check('extreme_valid_range_ood', row, True)
    # Construct an unseen discrete combination without modifying labels or data.
    row = dict(base)
    for _ in range(1000):
        row = dict(base)
        row['vendor_mismatch'] = rng.choice([0,1])
        row['unexpected_component'] = rng.choice([0,1])
        row['vulnerability_present'] = rng.choice([0,1])
        row['vulnerability_applicable'] = rng.choice([0,1])
        if 'unseen_binary_combination' in inspect_features(row,profile)['reasons']:
            break
    assert 'unseen_binary_combination' in inspect_features(row,profile)['reasons']
    check('ood_combination', row, True)
    for field in ['hash_mismatch','signature_invalid','trusted_root_invalid','vendor_untrusted','unauthorized_rollback']:
        hard = next(r for r in train_rows if r[field] == 1)
        assert assess_for_review(hard,profile)['ml_score'] is None
        cases.append({'case':'rejected_model_cannot_score_' + field, 'pass':True})
    return {'version':'correction-suite-1', 'seed':20260903, 'cases':cases, 'all_pass':True,
            'boundary':'Offline guard only. No policy decision is overwritten and no rejected model is activated.',
            'profile_fit_split':'train', 'not_used_for_fitting_or_selection':True}

def privacy_report():
    patterns = {'email':r'[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
                'ipv4':r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'private_key':r'-----BEGIN .*PRIVATE KEY-----',
                'phone':r'(?<!\w)\+\d[\d ()-]{8,18}\d(?!\w)'}
    forbidden = {'email','phone','full_name','first_name','last_name','address','dob','ip_address','user_id'}
    files, findings = [], []
    for path in sorted(DATA.glob('*.csv')):
        rows = read_csv(path)
        files.append({'path':path.relative_to(ROOT).as_posix(),'sha256':digest(path),'records':len(rows),'fields':list(rows[0]) if rows else []})
        for col in (rows[0] if rows else {}):
            if col.lower() in forbidden:
                findings.append({'file':path.name,'field':col,'kind':'pii_schema_field'})
        for i,row in enumerate(rows,2):
            for col,value in row.items():
                for kind,pattern in patterns.items():
                    if re.search(pattern,value):
                        findings.append({'file':path.name,'row':i,'field':col,'kind':kind})
    return {'scope':'Frozen dataset CSV fields and values only; does not scan proprietary firmware, binary models or arbitrary archives.',
            'schema_review':'Synthetic record/asset/vendor/product identifiers and evidence fields; no direct personal-data columns expected.',
            'files':files,'findings':findings,'status':'PASS_LIMITED_SCAN' if not findings else 'REVIEW_REQUIRED',
            'limitation':'Pattern checks are not proof of absence of all personal or confidential information.'}

def main(output):
    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.inspection import permutation_importance
    from threadpoolctl import threadpool_limits

    output.mkdir(parents=True, exist_ok=True)
    integrity = historical_integrity()
    splits = read_csv(DATA / 'split_assignments.csv')
    raw_features = read_csv(DATA / 'engineered_features.csv')
    assert list(raw_features[0]) == ['record_id', *FEATURES]
    features = {r['record_id']:{f:float(r[f]) for f in FEATURES} for r in raw_features}
    train_ids = [r['record_id'] for r in splits if r['split'] == 'train']
    test_ids = [r['record_id'] for r in splits if r['split'] == 'test']
    assert len(train_ids) == 3500 and len(test_ids) == 750 and not set(train_ids) & set(test_ids)
    profile = build_profile([features[i] for i in train_ids],train_ids)
    write_json(output / 'input_profile.json',profile)
    write_json(output / 'robustness_report.json',robustness_report(profile,[features[i] for i in train_ids]))
    predictions = read_csv(OLD / 'final_test_predictions.csv')
    assert len(predictions) == 750 and {r['record_id'] for r in predictions} == set(test_ids)
    assert len({r['record_id'] for r in predictions}) == 750
    labels = {r['record_id']:r['ground_truth_label'] for r in read_csv(DATA / 'ground_truth_labels.csv')}
    assert all(r['ground_truth_label'] == labels[r['record_id']] for r in predictions)
    observed = {r['record_id']:r for r in read_csv(DATA / 'observable_features.csv')}
    write_json(output / 'subgroup_evaluation.json',subgroup_report(predictions,observed,features))
    write_json(output / 'calibration_report.json',probability_report(predictions))
    write_json(output / 'privacy_scan.json',privacy_report())
    model_path = ROOT / 'models/ml/selected_calibrated_model.joblib'
    model = joblib.load(model_path)
    ids = [r['record_id'] for r in predictions]
    X = pd.DataFrame([features[i] for i in ids],columns=list(FEATURES))
    with threadpool_limits(limits=1):
        p = model.predict_proba(X)
        order = [list(model.classes_).index(c) for c in CLASSES]
        aligned = p[:,order]
        saved = np.array([[float(r['prob_' + c]) for c in CLASSES] for r in predictions])
        error = float(np.max(np.abs(aligned-saved)))
        assert error <= 1e-10, error
        assert model.predict(X).tolist() == [r['predicted_label'] for r in predictions]
        chosen = np.argmax(aligned,axis=1)
        deltas = []
        for f in FEATURES:
            ablated = X.copy(); ablated[f] = 0.0
            delta = model.predict_proba(ablated)[:,order] - aligned
            deltas.append(delta[np.arange(len(X)),chosen])
        records = []
        for i,record in enumerate(predictions):
            ranked = sorted(range(len(FEATURES)),key=lambda j:(-abs(float(deltas[j][i])),FEATURES[j]))[:5]
            records.append({'record_id':record['record_id'],'predicted_label':record['predicted_label'],
                            'model_sha256':digest(model_path),'probabilities':dict(zip(CLASSES,aligned[i].tolist())),
                            'uncertainty_one_minus_max_probability':float(1-max(aligned[i])),
                            'top_5':[{'feature':FEATURES[j],'baseline_value':0,'observed_value':features[record['record_id']][FEATURES[j]],
                                      'predicted_class_probability_delta':float(deltas[j][i])} for j in ranked]})
        write_json(output / 'explanation_report.json',{'method':'Zero one feature at a time; rank absolute change in ORIGINAL predicted-class probability',
                   'feature_file_sha256':digest(DATA/'engineered_features.csv'), 'split_file_sha256':digest(DATA/'split_assignments.csv'),
                   'feature_metadata_sha256':digest(DATA/'feature_metadata.json'), 'model_sha256':digest(model_path),
                   'scope':'All 750 existing frozen test predictions; post-hoc only', 'records_evaluated':len(records),'records':records,
                   'limitation':'Sensitivity, not causality; single-feature ablation can be outside the joint feature distribution and bypasses input guard for explanation only.'})
        # Reconstruct validation importance for the saved selected uncalibrated
        # model only. Other candidate objects were not supplied; never refit them.
        selected = joblib.load(ROOT / 'models/ml/selected_uncalibrated_model.joblib')
        val_ids = [r['record_id'] for r in splits if r['split'] == 'validation']
        VX = pd.DataFrame([features[i] for i in val_ids],columns=list(FEATURES))
        importance = permutation_importance(selected,VX,[labels[i] for i in val_ids],scoring='f1_macro',n_repeats=20,random_state=20260828,n_jobs=1)
        write_json(output / 'selected_validation_importance.json',{'split':'validation','seed':20260828,'repeats':20,'model_sha256':digest(ROOT / 'models/ml/selected_uncalibrated_model.joblib'),
                   'features':[{'feature':f,'mean':float(importance.importances_mean[j]),'std':float(importance.importances_std[j])} for j,f in enumerate(FEATURES)],
                   'coverage':'Selected saved model only. Required all-candidate importance remains unavailable because other fitted candidates were not supplied.'})
    write_json(output / 'reload_verification.json',{'records':750,'predictions_match':True,'max_probability_absolute_error':error,'tolerance':1e-10,'model_sha256':digest(model_path),'no_fitting':True})
    write_json(output / 'integrity_verification.json',integrity)
    packages = {d.metadata['Name']:d.version for d in importlib.metadata.distributions()}
    write_json(output / 'environment_record.json',{'python':platform.python_version(),'platform':platform.platform(),'packages':dict(sorted(packages.items())),
                'scope':'Correction review runtime, NOT the original training runtime','original_training_runtime':'Not supplied; original requirements are claims, not execution evidence',
                'original_git_commit':None,'code_identity':'See package_manifest.json for complete file hashes; source ZIPs do not contain a verifiable Git commit.'})
    write_json(output / 'review_status.json',{'package_correction_status':'IMPLEMENTED_PENDING_CLEAN_VALIDATION','experiment_v1_status':'REJECTED','training_performed':False,
                'new_holdout_generated':False,'fusion_api_dashboard_authorized':False,'unrecoverable_v1_gaps':['Original training runtime/log/commit absent','Only one anomaly configuration fitted','Supervised hyperparameter selection used validation across configurations','Validation anomaly gates failed before test was opened','All-candidate validation importance and logistic coefficients absent'],
                'next_gate':'Clean package validation and Nihar merge confirmation; then approve an Experiment v2 protocol and independent quarantined holdout if further modeling is required.'})
    print(f'Correction evidence generated: 19 historical hashes; 750 frozen predictions reproduced; 750 local explanations. Experiment remains REJECTED.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args().output)
