# Slop Detector

A native macOS menu bar app that detects AI-generated text. Highlight text anywhere, press **⌘⇧D**, and get an instant, explainable breakdown of what looks like slop.

No API calls. No network. Everything runs locally on-device.

## What it detects

**Heuristic engine** (always on, 250KB binary):
- **Invisible Unicode** — zero-width spaces, BOM, directional overrides
- **AI-style punctuation** — em dashes, curly quotes, horizontal ellipsis
- **LLM phrases** — "delve", "it's worth noting", "tapestry of", and 80+ more patterns
- **Statistical signals** — sentence uniformity, vocabulary diversity, hedge word density, burstiness
- **Grammar patterns** — passive voice, dropped subjects, tool personification
- **Watermarks** — Cyrillic/Greek homoglyphs, variation selectors, tag characters

**Neural model** (included, +128MB):
- DistilBERT fine-tuned on AI vs. human text ([rasbt/ai-text-detector-distilbert](https://huggingface.co/rasbt/ai-text-detector-distilbert), 99.74% accuracy)
- Runs via CoreML on Apple Neural Engine / GPU
- Scores are blended: 60% neural + 40% heuristic per paragraph

Text is split into paragraphs, scored independently, and rolled up to an overall AI percentage with an explainable breakdown.

## Install

```bash
git clone https://github.com/snowpackdata/slop-detector.git
cd slop-detector
make install
```

This compiles the binary, downloads the neural model (117 MB, one-time), packages everything into **Slop Detector.app**, and copies it to `/Applications`. Open it from Spotlight or your Applications folder — it runs as a menu bar app with no dock icon.

Requires macOS 13+ and Xcode command line tools (`xcode-select --install`).

## Usage

1. Launch **Slop Detector** — it appears in your menu bar as `slop`
2. Select text anywhere on your Mac
3. Press **⌘⇧D**
4. A popover shows the AI percentage and every signal it found

You can also click the menu bar icon and choose **Scan Clipboard**.

### Permissions

On first run, macOS will ask for **Accessibility** permissions (System Settings > Privacy & Security > Accessibility). This is needed to simulate ⌘C to grab selected text.

## Detection rules

Heuristic rules based on [llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT). Everything is compiled into the binary — no config files or runtime downloads.

| Category | Examples |
|----------|----------|
| Invisible chars | Zero-width space, BOM, soft hyphen |
| AI punctuation | Em dash, curly quotes, ellipsis |
| LLM phrases | "delve", "leverage", "tapestry of" |
| Statistical | Sentence uniformity, low vocab diversity |
| Grammar | Passive voice, dropped subjects, personification |
| Watermarks | Cyrillic homoglyphs, variation selectors |
| Neural | DistilBERT AI text classifier (CoreML) |

## Build

```bash
make build      # compile binary only
make setup      # download neural model (117 MB)
make app        # build + package .app bundle
make install    # build + install to /Applications
make run        # build + launch from terminal
make clean      # remove binary, model, and .app
```

## License

MIT. Detection rules derived from [mandakan/llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT).
