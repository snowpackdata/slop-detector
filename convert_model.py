#!/usr/bin/env python3
"""
Download a DistilBERT AI text detector, convert directly to CoreML
for native macOS inference. No ONNX intermediate step.

Model: rasbt/ai-text-detector-distilbert (99.74% accuracy)
"""

import os
import json
import shutil
import numpy as np

MODEL_NAME = "rasbt/ai-text-detector-distilbert"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
COREML_PATH = os.path.join(OUTPUT_DIR, "SlopDetectorModel.mlpackage")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Step 1: Download and test
    print(f"[1/3] Downloading {MODEL_NAME}...")
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    # Test
    def tokenize(text):
        t = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding="max_length")
        return {k: v for k, v in t.items() if k in ("input_ids", "attention_mask")}

    inputs = tokenize("This is clearly written by a human.")
    with torch.no_grad():
        probs = torch.softmax(model(**inputs).logits, dim=-1)
        print(f"   Human text → {probs[0].tolist()}")

    inputs2 = tokenize(
        "It's important to note that leveraging cutting-edge solutions in today's rapidly evolving landscape "
        "requires a holistic approach. Furthermore, by harnessing the power of innovative methodologies, "
        "organizations can seamlessly navigate the complexities of modern challenges."
    )
    with torch.no_grad():
        probs2 = torch.softmax(model(**inputs2).logits, dim=-1)
        print(f"   AI slop   → {probs2[0].tolist()}")

    # Step 2: Trace and convert to CoreML
    print("[2/3] Converting to CoreML (FP16)...")
    import coremltools as ct

    # Trace the model
    example_input_ids = torch.ones(1, 512, dtype=torch.long)
    example_attention_mask = torch.ones(1, 512, dtype=torch.long)

    class WrappedModel(torch.nn.Module):
        def __init__(self, model):
            super().__init__()
            self.model = model
        def forward(self, input_ids, attention_mask):
            return self.model(input_ids=input_ids, attention_mask=attention_mask).logits

    wrapped = WrappedModel(model)
    wrapped.eval()

    traced = torch.jit.trace(wrapped, (example_input_ids, example_attention_mask))

    coreml_model = ct.convert(
        traced,
        inputs=[
            ct.TensorType(name="input_ids", shape=(1, 512), dtype=np.int32),
            ct.TensorType(name="attention_mask", shape=(1, 512), dtype=np.int32),
        ],
        outputs=[
            ct.TensorType(name="logits"),
        ],
        minimum_deployment_target=ct.target.macOS13,
        compute_precision=ct.precision.FLOAT16,
    )

    coreml_model.author = "Snowpack Data"
    coreml_model.license = "MIT"
    coreml_model.short_description = "DistilBERT AI text detector (rasbt/ai-text-detector-distilbert, 99.74% acc)"
    coreml_model.version = "1.0"
    coreml_model.save(COREML_PATH)

    coreml_size = sum(
        os.path.getsize(os.path.join(dp, f))
        for dp, _, filenames in os.walk(COREML_PATH)
        for f in filenames
    ) / 1024 / 1024
    print(f"   CoreML model: {coreml_size:.1f} MB")

    # Step 3: Save tokenizer and labels for Swift
    print("[3/3] Saving tokenizer for Swift...")
    tokenizer.save_pretrained(OUTPUT_DIR)
    labels = model.config.id2label
    with open(os.path.join(OUTPUT_DIR, "labels.json"), "w") as f:
        json.dump(labels, f, indent=2)
    print(f"   Labels: {labels}")

    # Clean up unnecessary files
    for f in os.listdir(OUTPUT_DIR):
        fp = os.path.join(OUTPUT_DIR, f)
        if f.startswith("model") and f.endswith((".safetensors", ".bin", ".onnx")):
            os.remove(fp)
        if f == "config.json":
            os.remove(fp)

    print(f"\n✅ Done!")
    print(f"   CoreML:     {COREML_PATH} ({coreml_size:.1f} MB)")
    print(f"   Tokenizer:  {OUTPUT_DIR}/tokenizer.json")


if __name__ == "__main__":
    main()
