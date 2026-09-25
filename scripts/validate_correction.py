"""Read-only package validation. Successful exit never accepts Experiment v1."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.correction_evidence import historical_integrity, read_json, read_csv

def main():
    historical_integrity()
    manifest = read_json(ROOT/'package_manifest.json')
    assert manifest['experiment_v1_status']=='REJECTED'
    for name,expected in manifest['files'].items():
        path = ROOT/name
        assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==expected,name
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()
              and not any(part in {'.git','__pycache__','.pytest_cache','.venv'} for part in p.relative_to(ROOT).parts)
              and p.suffix != '.pyc'}
    assert actual == set(manifest['files']) | {'package_manifest.json'}, sorted(actual - set(manifest['files']) - {'package_manifest.json'})
    legacy = ['scripts/generate_scenarios.py','scripts/test_environment.py','src/supply_chain/hash_evidence.py']
    assert all(not (ROOT/n).exists() for n in legacy)
    assert (ROOT/'benchmarks/frameworks/framework_requirements.json').exists()
    report = read_json(ROOT/'artifacts/correction/explanation_report.json')
    expected_ids = {r['record_id'] for r in read_csv(ROOT/'artifacts/ml_experiment/final_test_predictions.csv')}
    assert len(report['records'])==750 and {r['record_id'] for r in report['records']}==expected_ids
    assert read_json(ROOT/'artifacts/correction/robustness_report.json')['all_pass']
    assert read_json(ROOT/'artifacts/correction/reload_verification.json')['predictions_match']
    assert read_json(ROOT/'artifacts/correction/review_status.json')['experiment_v1_status']=='REJECTED'
    print(f'[PASS] {len(manifest["files"])} correction-package hashes, 19 historical hashes, dataset hashes, restored framework files and 750 explanations')
    print('[STATUS] Package integrity passes. Experiment v1 remains REJECTED; no training or integration approval.')

if __name__=='__main__':
    main()
