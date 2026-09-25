"""Run correction validation, writing logs outside the sealed repository."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise SystemExit('Choose a log output directory outside the sealed repository')
    output.mkdir(parents=True,exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='correction-checks-',dir=output))
    # A fresh, narrowly scoped directory avoids the host global pytest temp area.
    temp = run/'pytest-temp'
    commands = [
        ['-m','pytest','-q','-p','no:cacheprovider','--basetemp',str(temp)],
        ['scripts/validate_dataset.py'],
        ['scripts/validate_grouped_split.py'],
        ['scripts/validate_schemas.py'],
        ['scripts/verify_evidence_bundle.py'],
        ['scripts/validate_correction.py'],
    ]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1', LOKY_MAX_CPU_COUNT='1', OMP_NUM_THREADS='1')
    records = []
    for i,command in enumerate(commands,1):
        proc = subprocess.run([sys.executable,*command],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        (run/f'{i:02d}.log').write_text(proc.stdout+proc.stderr,encoding='utf-8',newline='\n')
        records.append({'command':['python',*command],'exit_code':proc.returncode,'log':f'{i:02d}.log'})
        print(f'[{"PASS" if proc.returncode==0 else "FAIL"}] {" ".join(command[:3])}',flush=True)
    summary = {'checked_at_utc':datetime.now(timezone.utc).isoformat(),'python':sys.version,
               'results':records,'all_checks_pass':all(r['exit_code']==0 for r in records),
               'experiment_status':'REJECTED','training_performed':False}
    (run/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(f'Logs: {run}')
    print('Experiment v1 remains REJECTED regardless of package validation outcome.')
    raise SystemExit(0 if summary['all_checks_pass'] else 1)

if __name__=='__main__':
    main()
