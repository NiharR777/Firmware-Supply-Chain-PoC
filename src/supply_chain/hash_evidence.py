from pathlib import Path
import hashlib
import json


# =========================================================
# PROJECT PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

BASE_DIR = (
    PROJECT_ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
)

PACKAGE_DIR = BASE_DIR / "packages"

EVIDENCE_DIR = (
    BASE_DIR
    / "generated"
    / "evidence_bundles"
)


# =========================================================
# PACKAGE MAPPING
# =========================================================

PACKAGE_FILES = {
    "PKG-001": "PKG-001_2.4.1.bin",
    "PKG-002": "PKG-002_3.1.0.bin",
    "PKG-003": "PKG-003_1.8.2.bin",
    "PKG-004": "PKG-004_5.2.0.bin",
    "PKG-005": "PKG-005_4.0.1.bin",
}


# =========================================================
# SCENARIO-SPECIFIC HASH OVERRIDES
#
# SC-001 and SC-002 are intentionally defined as
# hash-mismatch scenarios in the synthetic ground truth.
#
# The same packages are reused by other scenarios
# such as SC-005 and SC-006, so the hash mismatch must
# be applied at the SCENARIO level rather than the
# PACKAGE level.
# =========================================================

SCENARIO_HASH_OVERRIDES = {
    "SC-001": (
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
    ),

    "SC-002": (
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    ),
}


# =========================================================
# TRUSTED PACKAGE HASHES
#
# These values represent the trusted SHA-256 hashes of
# the actual synthetic package files.
#
# Scenario-specific mismatch cases are handled separately
# through SCENARIO_HASH_OVERRIDES above.
# =========================================================

TRUSTED_VENDOR_HASHES = {
    "PKG-001": (
        "cd9a236677bcb1653e34e3035642008cac00d7b0f084245b43613cd63b67d1e1"
    ),

    "PKG-002": (
        "733786aeae512c44d1798b392fdf03f52f41ccbfc6352f832d93f692006152c8"
    ),

    "PKG-003": (
        "8aff73129a78565567c867ec0992a91d83cee4d2d77765e7800faa807a252a1c"
    ),

    "PKG-004": (
        "46bd590bb364cd9a028e6361197d8cf9e6e8b7911c774a6b3d5fee6ab4cb6e82"
    ),

    "PKG-005": (
        "21eb07df5642d1903dd67c92b73463c234c77b2502dff324948ebd010343a397"
    ),
}


# =========================================================
# SHA-256 CALCULATION
# =========================================================

def calculate_sha256(file_path: Path) -> str:
    """
    Calculate SHA-256 digest of a package file.
    """

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# =========================================================
# GENERATE HASH EVIDENCE
# =========================================================

def generate_hash_evidence(
    scenario_id: str,
    package_id: str,
) -> dict:
    """
    Calculate the actual package SHA-256 hash and compare it
    against the appropriate trusted reference hash.

    For SC-001 and SC-002, scenario-specific mismatching
    reference hashes are intentionally used because those
    scenarios are defined as hash-mismatch cases.
    """

    # -----------------------------------------------------
    # Validate package ID
    # -----------------------------------------------------

    if package_id not in PACKAGE_FILES:
        raise ValueError(
            f"Unknown package ID: {package_id}"
        )

    # -----------------------------------------------------
    # Validate trusted hash configuration
    # -----------------------------------------------------

    if package_id not in TRUSTED_VENDOR_HASHES:
        raise ValueError(
            f"No trusted hash configured for {package_id}"
        )

    # -----------------------------------------------------
    # Locate package
    # -----------------------------------------------------

    package_file = (
        PACKAGE_DIR
        / PACKAGE_FILES[package_id]
    )

    if not package_file.exists():
        raise FileNotFoundError(
            f"Package file not found: {package_file}"
        )

    # -----------------------------------------------------
    # Calculate actual package hash
    # -----------------------------------------------------

    calculated_hash = calculate_sha256(package_file)

    # -----------------------------------------------------
    # Select trusted reference
    #
    # Scenario override takes priority.
    # Otherwise use the normal trusted package hash.
    # -----------------------------------------------------

    trusted_vendor_hash = SCENARIO_HASH_OVERRIDES.get(
        scenario_id,
        TRUSTED_VENDOR_HASHES[package_id],
    )

    # -----------------------------------------------------
    # Compare hashes
    # -----------------------------------------------------

    hash_match = (
        calculated_hash.lower()
        == trusted_vendor_hash.lower()
    )

    # -----------------------------------------------------
    # Build evidence
    # -----------------------------------------------------

    return {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "package_file": package_file.name,
        "hash_algorithm": "SHA-256",
        "trusted_vendor_hash": trusted_vendor_hash,
        "calculated_package_hash": calculated_hash,
        "hash_match": hash_match,
        "integrity_status": (
            "PASSED"
            if hash_match
            else "FAILED"
        ),
        "data_provenance": "SYNTHETIC",
    }


# =========================================================
# SAVE HASH EVIDENCE
# =========================================================

def save_hash_evidence(
    scenario_id: str,
    package_id: str,
) -> dict:
    """
    Generate and save hash evidence for one scenario.
    """

    evidence = generate_hash_evidence(
        scenario_id=scenario_id,
        package_id=package_id,
    )

    output_dir = (
        EVIDENCE_DIR
        / scenario_id
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        output_dir
        / "hash_evidence.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            evidence,
            file,
            indent=2,
        )

    return evidence


# =========================================================
# GENERATE ALL HASH EVIDENCE
# =========================================================

def generate_all_hash_evidence():
    """
    Generate SHA-256 evidence for all ten refinery
    supply-chain scenarios.

    Package mapping is obtained from each scenario's
    package.json file.
    """

    for scenario_number in range(1, 11):

        scenario_id = (
            f"SC-{scenario_number:03d}"
        )

        scenario_dir = (
            EVIDENCE_DIR
            / scenario_id
        )

        package_file = (
            scenario_dir
            / "package.json"
        )

        # -------------------------------------------------
        # Check package metadata
        # -------------------------------------------------

        if not package_file.exists():
            print(
                f"{scenario_id} | package.json not found"
            )
            continue

        # -------------------------------------------------
        # Read package metadata
        # -------------------------------------------------

        with package_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            package_data = json.load(file)

        package_id = package_data.get(
            "package_id"
        )

        if not package_id:
            print(
                f"{scenario_id} | package_id missing"
            )
            continue

        # -------------------------------------------------
        # Generate evidence
        # -------------------------------------------------

        evidence = save_hash_evidence(
            scenario_id=scenario_id,
            package_id=package_id,
        )

        # -------------------------------------------------
        # Display result
        # -------------------------------------------------

        print(
            f"{scenario_id} | "
            f"{package_id} | "
            f"match={evidence['hash_match']} | "
            f"status={evidence['integrity_status']}"
        )


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    print()

    print(
        "===== SHA-256 PACKAGE HASH EVIDENCE GENERATION ====="
    )

    generate_all_hash_evidence()

    print()

    print(
        "===== SHA-256 EVIDENCE GENERATION COMPLETE ====="
    )