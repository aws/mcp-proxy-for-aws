#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# Script to generate SBOM for the project
# Usage: ./scripts/generate-sbom.sh [image-name:tag]

IMAGE_NAME="${1:-mcp-proxy-for-aws:latest}"
OUTPUT_DIR="${2:-./sbom}"

echo "Generating SBOM for ${IMAGE_NAME}..."

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Check if syft is installed
if ! command -v syft &> /dev/null; then
    echo "Error: syft is not installed. Please install it first:"
    echo "  brew install syft"
    echo "  or visit: https://github.com/anchore/syft"
    exit 1
fi

# Generate SBOM in SPDX format
echo "Generating SPDX SBOM..."
syft scan "${IMAGE_NAME}" -o spdx-json > "${OUTPUT_DIR}/sbom.spdx.json"

# Generate SBOM in CycloneDX format
echo "Generating CycloneDX SBOM..."
syft scan "${IMAGE_NAME}" -o cyclonedx-json > "${OUTPUT_DIR}/sbom.cyclonedx.json"

# Generate human-readable table format
if command -v cyclonedx &> /dev/null; then
    cyclonedx convert --input-file "${OUTPUT_DIR}/sbom.cyclonedx.json" --input-format json --output-format csv --output-file "${OUTPUT_DIR}/SBOM.csv"
else
    echo "Warning: cyclonedx CLI not found. Skipping CSV generation."
    echo "Install from: https://github.com/CycloneDX/cyclonedx-cli/releases"
fi

echo "SBOM generation complete!"
echo "Files created in ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}"
