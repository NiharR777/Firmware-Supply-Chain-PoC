from pathlib import Path
import hashlib
import json
import pandas as pd


# Project location
BASE_DIR = Path("data/synthetic/supply_chain_poc")

SCHEMA_DIR = BASE_DIR / "schemas"

PACKAGE_DIR = BASE_DIR / "packages"
SBOM_DIR = BASE_DIR / "sbom"
SIGNATURE_DIR = BASE_DIR / "signatures"
VEX_DIR = BASE_DIR / "vex"
ADVISORY_DIR = BASE_DIR / "advisories"
DEPLOYMENT_DIR = BASE_DIR / "deployments"
GENERATED_DIR = BASE_DIR / "generated"


# Create output folders if they don't already exist
for folder in [
    PACKAGE_DIR,
    SBOM_DIR,
    SIGNATURE_DIR,
    VEX_DIR,
    ADVISORY_DIR,
    DEPLOYMENT_DIR,
    GENERATED_DIR,
]:
    folder.mkdir(parents=True, exist_ok=True)


# Read the existing CSV files
packages = pd.read_csv(SCHEMA_DIR / "packages.csv")
components = pd.read_csv(SCHEMA_DIR / "components.csv")
dependencies = pd.read_csv(SCHEMA_DIR / "dependencies.csv")
assets = pd.read_csv(SCHEMA_DIR / "deployed_assets.csv")


# Calculate SHA-256 for a file
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(8192)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# Create a harmless synthetic package
def generate_package(package):
    package_id = package["package_id"]
    package_name = package["package_name"]
    version = package["current_version"]

    file_path = PACKAGE_DIR / f"{package_id}_{version}.bin"

    content = (
        "SYNTHETIC FIRMWARE PACKAGE\n"
        f"Package ID: {package_id}\n"
        f"Package Name: {package_name}\n"
        f"Version: {version}\n"
        "This file is generated only for the internship PoC.\n"
    )

    file_path.write_text(content, encoding="utf-8")

    package_hash = calculate_sha256(file_path)

    return file_path, package_hash


# Create a simple SBOM for the package
def generate_sbom(package):
    package_id = package["package_id"]

    package_dependencies = dependencies[
        dependencies["package_id"] == package_id
    ]

    component_list = []

    for _, dependency in package_dependencies.iterrows():

        component_id = dependency["component_id"]

        component = components[
            components["component_id"] == component_id
        ]

        if component.empty:
            continue

        component = component.iloc[0]

        component_list.append({
            "id": component["component_id"],
            "name": component["component_name"],
            "version": component["version"],
            "supplier": component["supplier"],
            "type": component["component_type"],
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{package_id}",
        "version": 1,
        "metadata": {
            "package_id": package_id,
            "package_name": package["package_name"],
            "package_version": package["current_version"],
        },
        "components": component_list,
    }

    output_file = SBOM_DIR / f"{package_id}_sbom.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(sbom, file, indent=2)

    return output_file


# Create a synthetic signature/attestation record
def generate_signature(package, package_hash):
    package_id = package["package_id"]

    record = {
        "package_id": package_id,
        "algorithm": "SHA-256",
        "package_hash": package_hash,
        "signature_status": "valid",
        "attestation_status": "valid",
        "trusted_root": True,
        "vendor_id": package["vendor_id"],
    }

    output_file = SIGNATURE_DIR / f"{package_id}_signature.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=2)

    return output_file


# Create package -> product -> deployed asset mapping
def generate_deployment(package):
    product_id = package["product_id"]

    product_assets = assets[
        assets["product_id"] == product_id
    ]

    asset_ids = product_assets["asset_id"].tolist()

    record = {
        "package_id": package["package_id"],
        "product_id": product_id,
        "affected_assets": asset_ids,
    }

    output_file = (
        DEPLOYMENT_DIR /
        f"{package['package_id']}_deployment.json"
    )

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=2)

    return output_file


# Generate all normal/reference packages
manifest_rows = []

for _, package in packages.iterrows():

    package_file, package_hash = generate_package(package)

    sbom_file = generate_sbom(package)

    signature_file = generate_signature(
        package,
        package_hash
    )

    deployment_file = generate_deployment(package)

    manifest_rows.append({
        "package_id": package["package_id"],
        "package_file": str(package_file),
        "sha256": package_hash,
        "sbom_file": str(sbom_file),
        "signature_file": str(signature_file),
        "deployment_file": str(deployment_file),
    })


# Save the generated package manifest
manifest = pd.DataFrame(manifest_rows)

manifest_file = (
    GENERATED_DIR /
    "generated_package_manifest.csv"
)

manifest.to_csv(
    manifest_file,
    index=False
)


print("Synthetic supply-chain data generated successfully.")
print(f"Packages generated: {len(manifest)}")
print(f"Manifest created: {manifest_file}")