#!/bin/bash
# Download and convert the DistilBERT AI text detector to CoreML.
# Requires Python 3 with: pip install transformers torch coremltools numpy
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -d "model/SlopDetectorModel.mlpackage" ] && [ -f "model/tokenizer.json" ]; then
    echo "Model already exists in model/. Delete model/ to re-download."
    exit 0
fi

echo "Checking Python dependencies..."
python3 -c "import transformers, torch, coremltools, numpy" 2>/dev/null || {
    echo "Missing dependencies. Install with:"
    echo "  pip install transformers torch coremltools numpy"
    exit 1
}

echo "Converting model (this downloads ~260MB and takes a few minutes)..."
python3 convert_model.py

echo ""
echo "Done! Run 'make run' to start slop-detector with neural scoring."
