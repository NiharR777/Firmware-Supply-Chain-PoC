from pathlib import Path
import pandas as pd

schema_dir = Path("data/synthetic/supply_chain_poc/schemas")

files = [
    "products.csv",
    "vendors.csv",
    "packages.csv",
    "components.csv",
    "dependencies.csv",
    "deployed_assets.csv",
    "vulnerabilities.csv",
    "vex_records.csv",
    "trusted_roots.csv",
    "package_evidence.csv",
]

print("Checking supply-chain schema files...\n")

for filename in files:
    path = schema_dir / filename

    if not path.exists():
        print(f"[ERROR] Missing: {filename}")
        continue

    df = pd.read_csv(path)

    print(f"[OK] {filename} -> {len(df)} records")

print("\nSchema validation completed.")