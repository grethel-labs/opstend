"""Pinned upstream tool archives; upgraded deliberately with acceptance evidence."""

from pathlib import Path

TRIVY_VERSION = "0.76.2"
TRIVY_BINARY = Path(f"/opt/steward/tools/trivy-{TRIVY_VERSION}/trivy")
TRIVY_ARCHIVES = {
    "x86_64": {
        "file": "trivy_0.76.2_Linux-64bit.tar.gz",
        "sha256": "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
    },
    "aarch64": {
        "file": "trivy_0.76.2_Linux-ARM64.tar.gz",
        "sha256": "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",
    },
}

RESTIC_VERSION = "0.19.1"
RESTIC_BINARY = Path(f"/opt/steward/tools/restic-{RESTIC_VERSION}/restic")
RESTIC_ARCHIVES = {
    "x86_64": {
        "file": "restic_0.19.1_linux_amd64.bz2",
        "sha256": "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c",
    },
    "aarch64": {
        "file": "restic_0.19.1_linux_arm64.bz2",
        "sha256": "a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465",
    },
}

# GitHub ollama/ollama releases/expanded_assets/v0.40.18, verified 2026-11-25.
OLLAMA_VERSION = "0.40.18"
OLLAMA_ARCHIVE = "ollama-linux-amd64.tar.zst"
OLLAMA_SHA256 = "b82649006cb5b54ed1237fa2d1a26a7f939a4fd03150033759acbff7ff315adf"
OLLAMA_BINARY = Path(f"/opt/steward/tools/ollama-{OLLAMA_VERSION}/bin/ollama")
