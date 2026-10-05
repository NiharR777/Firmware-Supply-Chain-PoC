"""
Dependency Topology Analysis
----------------------------

Purpose:
    Analyze firmware package -> component relationships from the
    synthetic SBOM/dependency dataset.

This module:
    1. Loads package, component and dependency schemas.
    2. Builds a directed dependency graph.
    3. Calculates topology features.
    4. Identifies shared and unusual components.
    5. Applies Isolation Forest to component topology features.
    6. Produces machine-readable evidence artifacts.

Important:
    This is topology/anomaly analysis only.
    It does NOT replace the existing deterministic decision engine.
    An anomaly is not automatically considered malicious.
"""

from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
import pandas as pd
from sklearn.ensemble import IsolationForest


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("data/synthetic/supply_chain_poc")

SCHEMA_DIR = BASE_DIR / "schemas"

PACKAGES_FILE = SCHEMA_DIR / "packages.csv"
COMPONENTS_FILE = SCHEMA_DIR / "components.csv"
DEPENDENCIES_FILE = SCHEMA_DIR / "dependencies.csv"

ARTIFACT_DIR = Path("artifacts/topology")


# ============================================================
# HELPERS
# ============================================================

def ensure_paths() -> None:
    """Create the topology artifact directory."""

    ARTIFACT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def load_data() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load package, component and dependency records."""

    required_files = [
        PACKAGES_FILE,
        COMPONENTS_FILE,
        DEPENDENCIES_FILE,
    ]

    for file_path in required_files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Required topology input not found: {file_path}"
            )

    packages = pd.read_csv(PACKAGES_FILE)
    components = pd.read_csv(COMPONENTS_FILE)
    dependencies = pd.read_csv(DEPENDENCIES_FILE)

    return packages, components, dependencies


def validate_data(
    packages: pd.DataFrame,
    components: pd.DataFrame,
    dependencies: pd.DataFrame,
) -> None:
    """Validate the minimum fields required for graph construction."""

    required_package_columns = {
        "package_id",
        "package_name",
        "current_version",
    }

    required_component_columns = {
        "component_id",
        "component_name",
        "version",
        "supplier",
        "component_type",
    }

    required_dependency_columns = {
        "package_id",
        "component_id",
        "dependency_type",
    }

    if not required_package_columns.issubset(packages.columns):
        missing = required_package_columns - set(packages.columns)
        raise ValueError(
            f"Missing package columns: {sorted(missing)}"
        )

    if not required_component_columns.issubset(components.columns):
        missing = required_component_columns - set(components.columns)
        raise ValueError(
            f"Missing component columns: {sorted(missing)}"
        )

    if not required_dependency_columns.issubset(
        dependencies.columns
    ):
        missing = required_dependency_columns - set(
            dependencies.columns
        )
        raise ValueError(
            f"Missing dependency columns: {sorted(missing)}"
        )

    package_ids = set(packages["package_id"])
    component_ids = set(components["component_id"])

    unknown_packages = set(
        dependencies["package_id"]
    ) - package_ids

    unknown_components = set(
        dependencies["component_id"]
    ) - component_ids

    if unknown_packages:
        raise ValueError(
            "Dependencies reference unknown packages: "
            + ", ".join(sorted(unknown_packages))
        )

    if unknown_components:
        raise ValueError(
            "Dependencies reference unknown components: "
            + ", ".join(sorted(unknown_components))
        )


# ============================================================
# GRAPH CONSTRUCTION
# ============================================================

def build_dependency_graph(
    packages: pd.DataFrame,
    components: pd.DataFrame,
    dependencies: pd.DataFrame,
) -> nx.DiGraph:
    """
    Build a directed bipartite-style dependency graph.

    Package node:
        PACKAGE:<package_id>

    Component node:
        COMPONENT:<component_id>

    Edge:
        PACKAGE -> COMPONENT
    """

    graph = nx.DiGraph()

    # --------------------------------------------------------
    # Add package nodes
    # --------------------------------------------------------

    for _, package in packages.iterrows():

        package_id = str(package["package_id"])

        graph.add_node(
            f"PACKAGE:{package_id}",
            node_type="package",
            package_id=package_id,
            name=str(package["package_name"]),
            version=str(package["current_version"]),
        )

    # --------------------------------------------------------
    # Add component nodes
    # --------------------------------------------------------

    for _, component in components.iterrows():

        component_id = str(component["component_id"])

        graph.add_node(
            f"COMPONENT:{component_id}",
            node_type="component",
            component_id=component_id,
            name=str(component["component_name"]),
            version=str(component["version"]),
            supplier=str(component["supplier"]),
            component_type=str(component["component_type"]),
        )

    # --------------------------------------------------------
    # Add dependency edges
    # --------------------------------------------------------

    for _, dependency in dependencies.iterrows():

        package_id = str(dependency["package_id"])
        component_id = str(dependency["component_id"])
        dependency_type = str(dependency["dependency_type"])

        graph.add_edge(
            f"PACKAGE:{package_id}",
            f"COMPONENT:{component_id}",
            dependency_type=dependency_type,
        )

    return graph


# ============================================================
# COMPONENT TOPOLOGY
# ============================================================

def calculate_component_features(
    components: pd.DataFrame,
    dependencies: pd.DataFrame,
) -> pd.DataFrame:
    """
    Calculate structural features for every component.

    Features:
        package_count
        component_degree
        supplier
        component_type
        shared_component
    """

    package_counts = (
        dependencies.groupby("component_id")["package_id"]
        .nunique()
        .rename("package_count")
    )

    dependency_counts = (
        dependencies.groupby("component_id")
        .size()
        .rename("dependency_count")
    )

    features = components.copy()

    features["package_count"] = (
        features["component_id"]
        .map(package_counts)
        .fillna(0)
        .astype(int)
    )

    features["dependency_count"] = (
        features["component_id"]
        .map(dependency_counts)
        .fillna(0)
        .astype(int)
    )

    # A component used by more than one package is shared.
    features["shared_component"] = (
        features["package_count"] > 1
    )

    return features


# ============================================================
# PACKAGE TOPOLOGY
# ============================================================

def calculate_package_features(
    packages: pd.DataFrame,
    dependencies: pd.DataFrame,
) -> pd.DataFrame:
    """Calculate dependency statistics for every firmware package."""

    dependency_counts = (
        dependencies.groupby("package_id")
        .size()
        .rename("dependency_count")
    )

    unique_component_counts = (
        dependencies.groupby("package_id")["component_id"]
        .nunique()
        .rename("unique_component_count")
    )

    features = packages.copy()

    features["dependency_count"] = (
        features["package_id"]
        .map(dependency_counts)
        .fillna(0)
        .astype(int)
    )

    features["unique_component_count"] = (
        features["package_id"]
        .map(unique_component_counts)
        .fillna(0)
        .astype(int)
    )

    return features


# ============================================================
# TOPOLOGY ANOMALY DETECTION
# ============================================================

def detect_component_anomalies(
    component_features: pd.DataFrame,
) -> pd.DataFrame:
    """
    Detect structurally unusual components using Isolation Forest.

    This is an anomaly detector, NOT a malware classifier.

    A component marked as an anomaly requires investigation.
    It does not automatically mean malicious.
    """

    result = component_features.copy()

    feature_columns = [
        "package_count",
        "dependency_count",
    ]

    model_input = result[feature_columns].astype(float)

    # --------------------------------------------------------
    # Small synthetic datasets require conservative handling.
    # --------------------------------------------------------

    if len(result) < 5:
        result["anomaly_score"] = 0.0
        result["anomaly_prediction"] = 1
        result["topology_anomaly"] = False
        return result

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )

    model.fit(model_input)

    result["anomaly_score"] = model.decision_function(
        model_input
    )

    result["anomaly_prediction"] = model.predict(
        model_input
    )

    result["topology_anomaly"] = (
        result["anomaly_prediction"] == -1
    )

    return result


# ============================================================
# GRAPH METRICS
# ============================================================

def calculate_graph_metrics(
    graph: nx.DiGraph,
) -> dict:
    """Calculate high-level graph statistics."""

    package_nodes = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("node_type") == "package"
    ]

    component_nodes = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("node_type") == "component"
    ]

    undirected_graph = graph.to_undirected()

    degree_centrality = nx.degree_centrality(
        undirected_graph
    )

    component_centrality = {
        node: degree_centrality.get(node, 0.0)
        for node in component_nodes
    }

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "package_nodes": len(package_nodes),
        "component_nodes": len(component_nodes),
        "density": nx.density(graph),
        "component_degree_centrality": component_centrality,
    }


# ============================================================
# REPORT GENERATION
# ============================================================

def create_topology_report(
    graph: nx.DiGraph,
    package_features: pd.DataFrame,
    component_features: pd.DataFrame,
) -> dict:
    """Create a readable JSON topology report."""

    graph_metrics = calculate_graph_metrics(graph)

    shared_components = component_features[
        component_features["shared_component"]
    ]

    topology_anomalies = component_features[
        component_features["topology_anomaly"]
    ]

    report = {
        "analysis": {
            "name": "Firmware Dependency Topology Analysis",
            "data_provenance": "SYNTHETIC SCHEMA DATA",
            "purpose": (
                "Analyze firmware package and component "
                "dependency relationships before deployment."
            ),
        },

        "algorithm": {
            "step_1": "Load package, component and dependency records.",
            "step_2": "Represent packages and components as graph nodes.",
            "step_3": "Represent package-to-component dependencies as directed edges.",
            "step_4": "Calculate dependency counts and component reuse.",
            "step_5": "Identify shared components across firmware packages.",
            "step_6": "Apply Isolation Forest to structural component features.",
            "step_7": "Flag topology anomalies for further investigation.",
            "step_8": (
                "Provide topology evidence to the broader security "
                "assessment without replacing deterministic controls."
            ),
        },

        "graph_metrics": graph_metrics,

        "shared_components": [
            {
                "component_id": str(row["component_id"]),
                "component_name": str(row["component_name"]),
                "version": str(row["version"]),
                "supplier": str(row["supplier"]),
                "component_type": str(row["component_type"]),
                "package_count": int(row["package_count"]),
            }
            for _, row in shared_components.iterrows()
        ],

        "topology_anomalies": [
            {
                "component_id": str(row["component_id"]),
                "component_name": str(row["component_name"]),
                "version": str(row["version"]),
                "supplier": str(row["supplier"]),
                "component_type": str(row["component_type"]),
                "package_count": int(row["package_count"]),
                "dependency_count": int(row["dependency_count"]),
                "anomaly_score": float(row["anomaly_score"]),
                "interpretation": (
                    "Structurally unusual component requiring "
                    "security investigation; not automatically malicious."
                ),
            }
            for _, row in topology_anomalies.iterrows()
        ],

        "packages": [
            {
                "package_id": str(row["package_id"]),
                "package_name": str(row["package_name"]),
                "current_version": str(row["current_version"]),
                "dependency_count": int(row["dependency_count"]),
                "unique_component_count": int(
                    row["unique_component_count"]
                ),
            }
            for _, row in package_features.iterrows()
        ],
    }

    return report


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run_topology_analysis() -> dict:
    """Run the complete dependency topology analysis."""

    print()
    print("=" * 70)
    print("FIRMWARE DEPENDENCY TOPOLOGY ANALYSIS")
    print("=" * 70)

    ensure_paths()

    # --------------------------------------------------------
    # 1. Load data
    # --------------------------------------------------------

    packages, components, dependencies = load_data()

    print()
    print("[1] Input data loaded")
    print(f"    Packages     : {len(packages)}")
    print(f"    Components   : {len(components)}")
    print(f"    Dependencies : {len(dependencies)}")

    # --------------------------------------------------------
    # 2. Validate
    # --------------------------------------------------------

    validate_data(
        packages,
        components,
        dependencies,
    )

    print("[2] Schema validation: PASSED")

    # --------------------------------------------------------
    # 3. Build graph
    # --------------------------------------------------------

    graph = build_dependency_graph(
        packages,
        components,
        dependencies,
    )

    print("[3] Dependency graph constructed")
    print(f"    Nodes : {graph.number_of_nodes()}")
    print(f"    Edges : {graph.number_of_edges()}")

    # --------------------------------------------------------
    # 4. Calculate topology features
    # --------------------------------------------------------

    component_features = calculate_component_features(
        components,
        dependencies,
    )

    package_features = calculate_package_features(
        packages,
        dependencies,
    )

    print("[4] Topology features calculated")

    # --------------------------------------------------------
    # 5. Detect topology anomalies
    # --------------------------------------------------------

    component_features = detect_component_anomalies(
        component_features
    )

    anomaly_count = int(
        component_features["topology_anomaly"].sum()
    )

    print(
        f"[5] Isolation Forest analysis complete "
        f"({anomaly_count} topology anomaly candidate(s))"
    )

    # --------------------------------------------------------
    # 6. Create report
    # --------------------------------------------------------

    report = create_topology_report(
        graph,
        package_features,
        component_features,
    )

    # --------------------------------------------------------
    # 7. Save outputs
    # --------------------------------------------------------

    component_output = (
        ARTIFACT_DIR / "component_topology_features.csv"
    )

    package_output = (
        ARTIFACT_DIR / "package_topology_features.csv"
    )

    report_output = (
        ARTIFACT_DIR / "topology_analysis.json"
    )

    graph_output = (
        ARTIFACT_DIR / "dependency_graph.graphml"
    )

    component_features.to_csv(
        component_output,
        index=False,
    )

    package_features.to_csv(
        package_output,
        index=False,
    )

    with report_output.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
        )

    nx.write_graphml(
        graph,
        graph_output,
    )

    # --------------------------------------------------------
    # 8. Summary
    # --------------------------------------------------------

    print()
    print("[6] Output artifacts created:")
    print(f"    {component_output}")
    print(f"    {package_output}")
    print(f"    {report_output}")
    print(f"    {graph_output}")

    print()
    print("=" * 70)
    print("TOPOLOGY ANALYSIS COMPLETE")
    print("=" * 70)

    print()
    print("Important:")
    print(
        "Topology anomalies are investigation candidates, "
        "not automatic malware classifications."
    )

    return report


if __name__ == "__main__":
    run_topology_analysis()