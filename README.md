# Slop Detector

A native macOS menu bar app that detects AI-generated text. Highlight text anywhere, press **⌘⇧D**, and get an instant, explainable breakdown of what looks like slop.

No API calls. No network. Everything runs locally in a 120KB binary.

## What it detects

- **Invisible Unicode** — zero-width spaces, BOM, directional overrides, and other characters that hide in text and wreck diffs
- **AI-style punctuation** — em dashes, curly quotes, horizontal ellipsis (the kind LLMs insert but humans rarely type)
- **LLM phrases** — "delve", "it's worth noting", "in today's fast-paced world", "tapestry of", "leverage", and 80+ more patterns

Output is explainable: "3× em dash, 'delve', zero-width joiner" — not a probability score.

## Install

```bash
# Clone and compile
git clone https://github.com/snowpackdata/slop-detector.git
cd slop-detector
make build

# Run
./slop-detector
```

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

Based on [llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT). Core rules are compiled into the binary — no config files needed.

| Category | Examples | Severity |
|----------|----------|----------|
| Invisible chars | Zero-width space, BOM, soft hyphen | ⚠️ Warning |
| AI punctuation | Em dash, curly quotes, ellipsis | 🔵 Info |
| LLM phrases | "delve", "leverage", "tapestry of" | 🔵 Info |

## Build

```bash
make build    # optimized release build
make run      # build and run
make clean    # remove binary
```

## License

MIT. Detection rules derived from [mandakan/llm-slop-detector](https://github.com/mandakan/llm-slop-detector) (MIT).
