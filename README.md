# Slop Detector

Menu bar app for macOS. Highlight text, hit **⌘⇧D**, see how much of it is AI.

Everything runs locally. No API calls, no network, no cloud. A 250KB binary and a 128MB neural model that lives on your machine.

## Install

```bash
git clone https://github.com/snowpackdata/slop-detector.git
cd slop-detector
make install
```

Opens from Spotlight or `/Applications`. Sits in your menu bar as `slop` — no dock icon, no terminal.

Needs macOS 13+ and Xcode CLI tools (`xcode-select --install`). First run asks for Accessibility permission so it can grab your selection.

## How it works

You select text anywhere on your Mac and press ⌘⇧D. The app copies it, splits it into paragraphs, and scores each one two ways:

**Neural model** — a DistilBERT classifier fine-tuned on AI vs. human text (99.74% accuracy on its eval set). Runs on CoreML, so it hits the Neural Engine on Apple Silicon. This is the heavy hitter.

**Heuristic rules** — pattern matching that catches things the model might miss and makes the output explainable:

- Invisible Unicode (zero-width spaces, BOM, directional overrides)
- AI punctuation (em dashes, curly quotes, horizontal ellipsis — the kind LLMs insert but people don't type)
- ~90 LLM phrases ("delve", "it's worth noting", "navigate the complexities")
- Statistical signals (sentence length uniformity, vocabulary repetition, hedge word density)
- Grammar tells (dropped subjects, passive voice, tool personification — "Fivetran has the headline")
- Watermarks (Cyrillic homoglyphs, variation selectors)

The final score blends both: 60% neural, 40% heuristic. The popover shows the overall percentage, per-paragraph scores, and every signal that fired.

## Updating

The app checks GitHub for new releases on launch. You can also click `slop` in the menu bar → **Check for Updates**. When there's a new version:

```bash
cd slop-detector
git pull
make install
```

## Build targets

```
make build      # compile the binary
make setup      # download the neural model (117 MB, one-time)
make app        # compile + package Slop Detector.app
make install    # all of the above + copy to /Applications
make run        # compile + run from terminal
make clean      # delete everything generated
```

## Credits

Detection rules started from [mandakan/llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT). Neural model is [rasbt/ai-text-detector-distilbert](https://huggingface.co/rasbt/ai-text-detector-distilbert).

MIT license.
