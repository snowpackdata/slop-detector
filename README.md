# Slop Detector

A native macOS menu bar app that detects AI-generated text. Highlight text anywhere, press **⌘⇧D**, and get an instant, explainable breakdown of what looks like slop.

No API calls. No network. Everything runs locally.

## What it detects

**Heuristic engine** (always on, 250KB binary):
- **Invisible Unicode** — zero-width spaces, BOM, directional overrides
- **AI-style punctuation** — em dashes, curly quotes, horizontal ellipsis
- **LLM phrases** — "delve", "it's worth noting", "tapestry of", and 80+ more patterns
- **Statistical signals** — sentence uniformity, vocabulary diversity, hedge word density, burstiness
- **Grammar patterns** — passive voice, dropped subjects, tool personification
- **Watermarks** — Cyrillic/Greek homoglyphs, variation selectors, tag characters

**Neural model** (optional, +128MB):
- DistilBERT fine-tuned on AI vs. human text ([rasbt/ai-text-detector-distilbert](https://huggingface.co/rasbt/ai-text-detector-distilbert), 99.74% accuracy)
- Runs via CoreML on Apple Neural Engine / GPU
- Scores are blended: 60% neural + 40% heuristic per paragraph

Text is split into paragraphs, scored independently, and rolled up to an overall AI percentage with an explainable breakdown.

## Install

```bash
git clone https://github.com/snowpackdata/slop-detector.git
cd slop-detector
make run
```

`make run` compiles the binary, downloads the neural model (117 MB, one-time), and launches the app.

Requires macOS and Xcode command line tools (`xcode-select --install`).

## Usage

1. Run `./slop-detector` — it lives in your menu bar as `slop`
2. Select text anywhere on your Mac
3. Press **⌘⇧D**
4. A popover shows every flag with its explanation

You can also click the menu bar icon → "Scan Clipboard" to scan whatever's on your clipboard.

### Permissions

On first run, macOS will ask for **Accessibility** permissions (System Settings → Privacy & Security → Accessibility). This is needed to simulate ⌘C to grab selected text.

## Detection rules

Heuristic rules based on [llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT). Core rules are compiled into the binary — no config files needed.

| Category | Examples | Severity |
|----------|----------|----------|
| Invisible chars | Zero-width space, BOM, soft hyphen | ⚠️ Warning |
| AI punctuation | Em dash, curly quotes, ellipsis | 🔵 Info |
| LLM phrases | "delve", "leverage", "tapestry of" | 🔵 Info |
| Statistical | Sentence uniformity, low vocab diversity | 📊 Info |
| Grammar | Passive voice, dropped subjects, personification | 📝 Info |
| Watermarks | Cyrillic homoglyphs, variation selectors | 🚨 Alert |
| Neural (optional) | DistilBERT AI text classifier | N/A |

## Build

```bash
make build    # compile binary only
make setup    # download neural model (117 MB)
make run      # build + setup + launch
make clean    # remove binary and model
```

## License

MIT. Detection rules derived from [mandakan/llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT).
