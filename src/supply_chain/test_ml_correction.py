"""Regression tests for the correction gate, not model-training acceptance."""
import copy
import json
from pathlib import Path

import pytest

from scripts.correction_evidence import classification_counts, historical_integrity, read_csv, subgroup_report
from src.supply_chain.ml_input_guard import FEATURES, inspect_features, assess_for_review

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data/synthetic/supply_chain_poc/dataset'

@pytest.fixture
def inputs():
    profile = json.loads((ROOT / 'artifacts/correction/input_profile.json').read_text())
    rows = {r['record_id']:r for r in read_csv(DATA / 'engineered_features.csv')}
    row = {f:float(rows[profile['fit_record_ids'][0]][f]) for f in FEATURES}
    return row,profile

@pytest.mark.parametrize('bad',[None,'1',float('nan'),float('inf'),float('-inf')])
def test_bad_numeric_values_abstain_without_coercion(inputs,bad):
    row,profile = inputs
    for feature in FEATURES:
        altered = {**row,feature:bad}
        result = inspect_features(altered,profile)
        assert result['status'] == 'ABSTAIN' and result['ml_score'] is None
        assert result['review_route'] == 'investigate'

def test_missing_and_extra_features_abstain(inputs):
    row,profile = inputs
    for feature in FEATURES:
        altered = dict(row); del altered[feature]
        assert inspect_features(altered,profile)['status'] == 'ABSTAIN'
    for forbidden in ['scenario_type','expected_decision','record_id','ground_truth_label']:
        assert inspect_features({**row,forbidden:'x'},profile)['status'] == 'ABSTAIN'

def test_contradiction_and_extreme_abstain(inputs):
    row,profile = inputs
    assert inspect_features({**row,'hard_failure_count':row['hard_failure_count']+1},profile)['status'] == 'ABSTAIN'
    assert inspect_features({**row,'package_size_mb':1e9},profile)['status'] == 'ABSTAIN'

def test_profile_uses_exact_train_ids_only(inputs):
    row,profile = inputs
    splits = read_csv(DATA / 'split_assignments.csv')
    assert set(profile['fit_record_ids']) == {r['record_id'] for r in splits if r['split'] == 'train'}
    assert inspect_features(row,profile)['status'] == 'INPUT_VALID'
    assert assess_for_review(row,profile)['status'] == 'ABSTAIN'
    assert 'experiment_not_accepted' in assess_for_review(row,profile)['reasons']

def test_guard_does_not_modify_input_or_policy(inputs):
    row,profile = inputs
    before = copy.deepcopy(row)
    assess_for_review(row,profile)
    assert row == before
    assert not {'risk_score','decision','risk_level'} & set(assess_for_review(row,profile))

def test_zero_denominators_are_not_reported_as_zero_errors():
    rows = [{'ground_truth_label':'high_risk','predicted_label':'high_risk'}]*35
    counts = classification_counts(rows)
    assert counts['per_class']['high_risk']['fpr'] is None
    assert counts['per_class']['normal']['recall'] is None
    assert counts['per_class']['high_risk']['recall'] == 1

def test_subgroup_gate_detects_real_gap():
    rows = []
    observed,features = {},{}
    for i in range(100):
        rid = str(i)
        truth = 'high_risk' if i % 2 == 0 else 'normal'
        rows.append({'record_id':rid,'ground_truth_label':truth,'predicted_label':'normal' if i < 40 else truth})
        observed[rid] = {'observed_vendor_id':'A' if i<40 else 'B','product_id':'P','lineage_id':rid}
        features[rid] = {f:0 for f in FEATURES}
    result = subgroup_report(rows,observed,features)
    group = next(g for g in result['groups'] if g['dimension']=='observed_vendor_id' and g['group']=='A')
    assert group['status']=='FAIL' and group['gate_checks']['recall']=='FAIL'

def test_historical_hashes_and_rejection_are_preserved():
    assert historical_integrity()['all_pass']

def test_explanation_ids_and_feature_contract():
    report = json.loads((ROOT / 'artifacts/correction/explanation_report.json').read_text())
    preds = read_csv(ROOT / 'artifacts/ml_experiment/final_test_predictions.csv')
    assert len(report['records']) == 750
    assert {r['record_id'] for r in report['records']} == {r['record_id'] for r in preds}
    assert all(len(r['top_5']) == 5 and len({f['feature'] for f in r['top_5']}) == 5 for r in report['records'])
    assert all(f['feature'] in FEATURES for r in report['records'] for f in r['top_5'])

def test_legacy_files_are_absent_from_active_tree():
    for relative in ['scripts/generate_scenarios.py','scripts/test_environment.py','src/supply_chain/hash_evidence.py']:
        assert not (ROOT/relative).exists()
    assert (ROOT/'scripts/framework_benchmark.py').exists()
    assert (ROOT/'evidence/v1/original_submission.zip').exists()

def test_saved_model_reproduces_frozen_predictions():
    import joblib
    import numpy as np
    import pandas as pd
    from threadpoolctl import threadpool_limits
    historical_integrity()
    model = joblib.load(ROOT/'models/ml/selected_calibrated_model.joblib')
    rows = pd.read_csv(DATA/'engineered_features.csv').set_index('record_id')
    predictions = read_csv(ROOT/'artifacts/ml_experiment/final_test_predictions.csv')
    X = rows.loc[[r['record_id'] for r in predictions],list(FEATURES)]
    with threadpool_limits(limits=1):
        probabilities = model.predict_proba(X)
        assert model.predict(X).tolist()==[r['predicted_label'] for r in predictions]
    expected = np.array([[float(r['prob_'+str(c)]) for c in model.classes_] for r in predictions])
    assert np.max(np.abs(probabilities-expected)) <= 1e-10
