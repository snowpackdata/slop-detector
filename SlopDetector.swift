import Cocoa
import Carbon

// MARK: - Detection Engine (based on llm-slop-detector, MIT license)
// Rules derived from github.com/mandakan/llm-slop-detector

struct Finding {
    enum Severity: String { case warning, info }
    let severity: Severity
    let name: String
    let reason: String
    let count: Int
    let positions: [Int]  // character offsets
}

struct ScanResult {
    let findings: [Finding]
    var isEmpty: Bool { findings.isEmpty }
    var totalFlags: Int { findings.reduce(0) { $0 + $1.count } }
}

class SlopScanner {

    // ── Invisible / suspicious Unicode chars ──────────────────────────
    struct CharRule {
        let char: Character
        let scalar: UInt32
        let name: String
        let severity: Finding.Severity
    }

    static let charRules: [CharRule] = [
        // Invisible / zero-width (warnings)
        CharRule(char: "\u{200B}", scalar: 0x200B, name: "ZERO WIDTH SPACE", severity: .warning),
        CharRule(char: "\u{200C}", scalar: 0x200C, name: "ZERO WIDTH NON-JOINER", severity: .warning),
        CharRule(char: "\u{200D}", scalar: 0x200D, name: "ZERO WIDTH JOINER", severity: .warning),
        CharRule(char: "\u{200E}", scalar: 0x200E, name: "LEFT-TO-RIGHT MARK", severity: .warning),
        CharRule(char: "\u{200F}", scalar: 0x200F, name: "RIGHT-TO-LEFT MARK", severity: .warning),
        CharRule(char: "\u{2060}", scalar: 0x2060, name: "WORD JOINER", severity: .warning),
        CharRule(char: "\u{FEFF}", scalar: 0xFEFF, name: "BOM / ZERO WIDTH NO-BREAK SPACE", severity: .warning),
        CharRule(char: "\u{00AD}", scalar: 0x00AD, name: "SOFT HYPHEN", severity: .warning),
        CharRule(char: "\u{00A0}", scalar: 0x00A0, name: "NO-BREAK SPACE", severity: .warning),
        CharRule(char: "\u{202F}", scalar: 0x202F, name: "NARROW NO-BREAK SPACE", severity: .warning),
        CharRule(char: "\u{202A}", scalar: 0x202A, name: "LEFT-TO-RIGHT EMBEDDING", severity: .warning),
        CharRule(char: "\u{202B}", scalar: 0x202B, name: "RIGHT-TO-LEFT EMBEDDING", severity: .warning),
        CharRule(char: "\u{202C}", scalar: 0x202C, name: "POP DIRECTIONAL FORMATTING", severity: .warning),
        CharRule(char: "\u{202D}", scalar: 0x202D, name: "LEFT-TO-RIGHT OVERRIDE", severity: .warning),
        CharRule(char: "\u{202E}", scalar: 0x202E, name: "RIGHT-TO-LEFT OVERRIDE", severity: .warning),
        CharRule(char: "\u{2066}", scalar: 0x2066, name: "LEFT-TO-RIGHT ISOLATE", severity: .warning),
        CharRule(char: "\u{2067}", scalar: 0x2067, name: "RIGHT-TO-LEFT ISOLATE", severity: .warning),
        CharRule(char: "\u{2068}", scalar: 0x2068, name: "FIRST STRONG ISOLATE", severity: .warning),
        CharRule(char: "\u{2069}", scalar: 0x2069, name: "POP DIRECTIONAL ISOLATE", severity: .warning),
        CharRule(char: "\u{180E}", scalar: 0x180E, name: "MONGOLIAN VOWEL SEPARATOR", severity: .warning),
        CharRule(char: "\u{1160}", scalar: 0x1160, name: "HANGUL FILLER", severity: .warning),
        CharRule(char: "\u{3164}", scalar: 0x3164, name: "HANGUL FILLER", severity: .warning),
        CharRule(char: "\u{2028}", scalar: 0x2028, name: "LINE SEPARATOR", severity: .warning),
        CharRule(char: "\u{2029}", scalar: 0x2029, name: "PARAGRAPH SEPARATOR", severity: .warning),

        // AI-style punctuation (info)
        CharRule(char: "\u{2014}", scalar: 0x2014, name: "EM DASH", severity: .info),
        CharRule(char: "\u{2013}", scalar: 0x2013, name: "EN DASH", severity: .info),
        CharRule(char: "\u{2026}", scalar: 0x2026, name: "HORIZONTAL ELLIPSIS", severity: .info),
        CharRule(char: "\u{201C}", scalar: 0x201C, name: "LEFT DOUBLE QUOTE", severity: .info),
        CharRule(char: "\u{201D}", scalar: 0x201D, name: "RIGHT DOUBLE QUOTE", severity: .info),
        CharRule(char: "\u{2018}", scalar: 0x2018, name: "LEFT SINGLE QUOTE", severity: .info),
        CharRule(char: "\u{2019}", scalar: 0x2019, name: "RIGHT SINGLE QUOTE", severity: .info),
    ]

    // ── Phrase patterns ───────────────────────────────────────────────
    struct PhraseRule {
        let pattern: String
        let reason: String
        let regex: NSRegularExpression
    }

    static let phraseRules: [PhraseRule] = {
        let raw: [(String, String)] = [
            // Core builtin rules
            (#"\bdelve(s|d|ing)?\b"#, "LLM filler"),
            (#"\bit'?s worth noting\b"#, "LLM hedge"),
            (#"\bit'?s important to note\b"#, "LLM hedge"),
            (#"\bin the ever[- ]evolving landscape\b"#, "LLM cliché"),
            (#"\bin today'?s fast[- ]paced world\b"#, "LLM cliché"),
            (#"\bnavigate the complexit(y|ies)\b"#, "LLM cliché"),
            (#"\ba testament to\b"#, "LLM filler"),
            (#"\btapestry of\b"#, "LLM filler"),
            (#"\brich tapestry\b"#, "LLM filler"),
            (#"\bat the heart of\b"#, "LLM filler"),
            (#"\bcrucial role\b"#, "LLM filler"),
            (#"\bplay(s|ed|ing)? a (crucial|pivotal|key|vital) role\b"#, "LLM filler"),
            (#"\bharness(es|ed|ing)? the power of\b"#, "LLM filler"),
            (#"\bunlock(s|ed|ing)? the (potential|power|secrets)\b"#, "LLM filler"),
            (#"\bleverag(e|es|ed|ing)\b"#, "corporate-speak"),
            (#"\bembark(s|ed|ing)? on (a|this) journey\b"#, "LLM cliché"),
            (#"\brealm of\b"#, "LLM filler"),
            (#"\bmultifaceted\b"#, "LLM filler"),
            (#"\bmeticulous(ly)?\b"#, "LLM filler"),
            (#"\bunderscore(s|d)?\b"#, "LLM filler"),
            (#"\bparamount\b"#, "LLM filler"),
            (#"\bdive (in|into|deeper)\b"#, "LLM filler"),
            (#"\bin conclusion,\b"#, "LLM structure"),
            (#"\bwhen it comes to\b"#, "LLM filler"),
            (#"\bthat said,\b"#, "LLM hedge"),
            (#"\bhowever, it'?s\b"#, "LLM hedge"),
            (#"\boverall,\b"#, "LLM structure"),
            (#"\bultimately,\b"#, "LLM structure"),
            (#"\bfoster(s|ed|ing)?\b"#, "LLM filler"),
            (#"\bbustling\b"#, "LLM filler"),
            (#"\bgame[- ]chang(er|ing)\b"#, "buzzword"),
            (#"\bcutting[- ]edge\b"#, "buzzword"),
            (#"\bstate[- ]of[- ]the[- ]art\b"#, "buzzword"),
            (#"\brevolutioniz(e|es|ed|ing)\b"#, "LLM filler"),
            (#"\bseamless(ly)?\b"#, "LLM filler"),
            (#"\brobust\b"#, "LLM filler"),
            (#"\bholistic\b"#, "LLM filler"),
            (#"\bsynerg(y|ies|istic)\b"#, "corporate-speak"),
            (#"\bparadigm shift\b"#, "buzzword"),

            // Clichés pack
            (#"\bcaptivating\b"#, "LLM cliché"),
            (#"\bdistinguished\b"#, "LLM cliché"),
            (#"\besteemed\b"#, "LLM cliché"),
            (#"\bexquisite\b"#, "LLM cliché"),
            (#"\bindomitable\b"#, "LLM cliché"),
            (#"\bpioneering\b"#, "LLM cliché"),
            (#"\bprofound\b"#, "LLM cliché"),
            (#"\bprominent\b"#, "LLM cliché"),
            (#"\bquintessential\b"#, "LLM cliché"),
            (#"\btangible\b"#, "LLM cliché"),
            (#"\btrailblazing\b"#, "LLM cliché"),
            (#"\bubiquitous\b"#, "LLM cliché"),
            (#"\bunwavering\b"#, "LLM cliché"),
            (#"\bunyielding\b"#, "LLM cliché"),
            (#"\bvisionary\b"#, "LLM cliché"),
            (#"\bepitome\b"#, "LLM cliché"),
            (#"\bfacet(s)?\b"#, "LLM cliché"),
            (#"\bpinnacle\b"#, "LLM cliché"),
            (#"\bsymphony of\b"#, "LLM cliché"),
            (#"\benvision(s|ed|ing)?\b"#, "LLM cliché"),
            (#"\bgalvaniz(e|es|ed|ing)\b"#, "LLM cliché"),
            (#"\btranscend(s|ed|ing)?\b"#, "LLM cliché"),
            (#"\bunleash(es|ed|ing)?\b"#, "LLM cliché"),
            (#"\busher(s|ed|ing)? in\b"#, "LLM cliché"),
            (#"\blandscape of\b"#, "LLM cliché"),
            (#"\bspectrum of\b"#, "LLM cliché"),

            // Extra high-signal phrases (email/message slop)
            (#"\bi hope this (helps|email finds you)\b"#, "LLM greeting"),
            (#"\bi'?d be happy to help\b"#, "LLM greeting"),
            (#"\bdon'?t hesitate to reach out\b"#, "LLM sign-off"),
            (#"\bplease don'?t hesitate\b"#, "LLM sign-off"),
            (#"\bhappy to discuss further\b"#, "LLM sign-off"),
            (#"\bgreat question\b"#, "LLM filler"),
            (#"\blet me break this down\b"#, "LLM structure"),
            (#"\blet'?s (dive|unpack)\b"#, "LLM structure"),
            (#"\bhere'?s a breakdown\b"#, "LLM structure"),
            (#"\bkey takeaways?\b"#, "LLM structure"),
            (#"\bin today'?s digital\b"#, "LLM cliché"),
            (#"\bin today'?s rapidly\b"#, "LLM cliché"),
            (#"\bcornerstone\b"#, "LLM filler"),
            (#"\bpivotal\b"#, "LLM filler"),
            (#"\bnuanced\b"#, "LLM filler"),
            (#"\bcommendable\b"#, "LLM filler"),
            (#"\bintricate(s|ly)?\b"#, "LLM filler"),
            (#"\bintricacies\b"#, "LLM filler"),
            (#"\bakin to\b"#, "LLM filler"),
            (#"\bhenceforth\b"#, "LLM filler"),
            (#"\bthereof\b"#, "LLM filler"),
            (#"\btherein\b"#, "LLM filler"),
            (#"\bwhilst\b"#, "LLM filler"),
            (#"\belevat(e|es|ed|ing)\b"#, "LLM filler"),
            (#"\bspearhead(s|ed|ing)?\b"#, "LLM filler"),
            (#"\bresonate(s)?\b"#, "LLM filler"),
            (#"\bstreamlin(e|es|ed|ing)\b"#, "LLM filler"),
            (#"\bempow(er|ers|ered|ering)\b"#, "LLM filler"),
        ]
        return raw.compactMap { (pattern, reason) in
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
            // Extract a human-readable name from the pattern
            return PhraseRule(pattern: pattern, reason: reason, regex: regex)
        }
    }()

    func scan(_ text: String) -> ScanResult {
        var findings: [Finding] = []

        // 1. Scan for suspicious characters
        for rule in SlopScanner.charRules {
            var positions: [Int] = []
            for (i, ch) in text.enumerated() {
                if ch == rule.char { positions.append(i) }
            }
            if !positions.isEmpty {
                findings.append(Finding(
                    severity: rule.severity,
                    name: rule.name,
                    reason: rule.severity == .warning ? "invisible/suspicious Unicode" : "AI-style punctuation",
                    count: positions.count,
                    positions: positions
                ))
            }
        }

        // 2. Scan for phrase patterns
        let nsText = text as NSString
        let fullRange = NSRange(location: 0, length: nsText.length)

        for rule in SlopScanner.phraseRules {
            let matches = rule.regex.matches(in: text, range: fullRange)
            if !matches.isEmpty {
                let positions = matches.map { $0.range.location }
                let firstMatch = nsText.substring(with: matches[0].range)
                findings.append(Finding(
                    severity: .info,
                    name: "\"\(firstMatch)\"",
                    reason: rule.reason,
                    count: matches.count,
                    positions: positions
                ))
            }
        }

        return ScanResult(findings: findings)
    }
}


// MARK: - Result Formatting

func formatResult(_ result: ScanResult, text: String) -> (title: String, body: String, console: String) {
    let wordCount = text.split(separator: " ").count

    if result.isEmpty {
        return (
            "Clean",
            "No slop detected in \(wordCount) words.",
            "✅ Clean — no slop detected in \(wordCount) words."
        )
    }

    let warnings = result.findings.filter { $0.severity == .warning }
    let infos = result.findings.filter { $0.severity == .info }

    // Title
    let title: String
    if !warnings.isEmpty {
        title = "⚠️  \(result.totalFlags) flag\(result.totalFlags == 1 ? "" : "s") in \(wordCount) words"
    } else {
        title = "🔵 \(result.totalFlags) flag\(result.totalFlags == 1 ? "" : "s") in \(wordCount) words"
    }

    // Notification body (compact)
    var bodyParts: [String] = []
    for f in result.findings.prefix(6) {
        let countStr = f.count > 1 ? "\(f.count)× " : ""
        bodyParts.append("\(countStr)\(f.name)")
    }
    if result.findings.count > 6 {
        bodyParts.append("… and \(result.findings.count - 6) more")
    }
    let body = bodyParts.joined(separator: ", ")

    // Console output (detailed)
    var console = "\n══════════════════════════════════════════════\n"
    console += "  SLOP SCAN: \(result.totalFlags) flag\(result.totalFlags == 1 ? "" : "s") in \(wordCount) words\n"
    console += "══════════════════════════════════════════════\n"

    if !warnings.isEmpty {
        console += "\n  ⚠️  WARNINGS (invisible/suspicious characters)\n"
        console += "  ─────────────────────────────────────────────\n"
        for f in warnings {
            let countStr = f.count > 1 ? " (×\(f.count))" : ""
            console += "  ⚠️  \(f.name)\(countStr)\n"
        }
    }

    let phrases = infos.filter { $0.name.hasPrefix("\"") }
    let punctuation = infos.filter { !$0.name.hasPrefix("\"") }

    if !punctuation.isEmpty {
        console += "\n  🔵 AI-STYLE PUNCTUATION\n"
        console += "  ─────────────────────────────────────────────\n"
        for f in punctuation {
            let countStr = f.count > 1 ? " (×\(f.count))" : ""
            console += "  🔵 \(f.name)\(countStr)\n"
        }
    }

    if !phrases.isEmpty {
        console += "\n  🔵 LLM PHRASES\n"
        console += "  ─────────────────────────────────────────────\n"
        for f in phrases {
            let countStr = f.count > 1 ? " (×\(f.count))" : ""
            console += "  🔵 \(f.name)\(countStr) — \(f.reason)\n"
        }
    }

    let preview = String(text.prefix(80)).replacingOccurrences(of: "\n", with: " ")
    console += "\n  Text: \"\(preview)…\"\n"
    console += "══════════════════════════════════════════════\n"

    return (title, body, console)
}


// MARK: - Popover Result View

class ResultViewController: NSViewController {
    let result: ScanResult
    let scannedText: String

    init(result: ScanResult, text: String) {
        self.result = result
        self.scannedText = text
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 10))

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: container.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)

        let wordCount = scannedText.split(separator: " ").count

        // Header
        let headerText: String
        let headerColor: NSColor
        if result.isEmpty {
            headerText = "✅  Clean — no slop detected"
            headerColor = .systemGreen
        } else if result.findings.contains(where: { $0.severity == .warning }) {
            headerText = "⚠️  \(result.totalFlags) flag\(result.totalFlags == 1 ? "" : "s") found"
            headerColor = .systemOrange
        } else {
            headerText = "🔵 \(result.totalFlags) flag\(result.totalFlags == 1 ? "" : "s") found"
            headerColor = .systemBlue
        }

        let header = NSTextField(labelWithString: headerText)
        header.font = .systemFont(ofSize: 16, weight: .semibold)
        header.textColor = headerColor
        stack.addArrangedSubview(header)

        let subtitle = NSTextField(labelWithString: "\(wordCount) words scanned")
        subtitle.font = .systemFont(ofSize: 11)
        subtitle.textColor = .secondaryLabelColor
        stack.addArrangedSubview(subtitle)

        if !result.isEmpty {
            let sep = NSBox()
            sep.boxType = .separator
            sep.translatesAutoresizingMaskIntoConstraints = false
            stack.addArrangedSubview(sep)
            sep.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -32).isActive = true

            let warnings = result.findings.filter { $0.severity == .warning }
            let infos = result.findings.filter { $0.severity == .info }
            let phrases = infos.filter { $0.name.hasPrefix("\"") }
            let punctuation = infos.filter { !$0.name.hasPrefix("\"") }

            if !warnings.isEmpty {
                addSection(to: stack, title: "⚠️  Invisible / suspicious characters", items: warnings, showReason: false)
            }
            if !punctuation.isEmpty {
                addSection(to: stack, title: "🔵 AI-style punctuation", items: punctuation, showReason: false)
            }
            if !phrases.isEmpty {
                addSection(to: stack, title: "🔵 LLM phrases", items: phrases, showReason: true)
            }
        }

        // Text preview
        let sep2 = NSBox()
        sep2.boxType = .separator
        sep2.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(sep2)
        sep2.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -32).isActive = true

        let preview = String(scannedText.prefix(200)).replacingOccurrences(of: "\n", with: " ")
        let previewField = NSTextField(wrappingLabelWithString: "\"\(preview)…\"")
        previewField.font = .systemFont(ofSize: 10)
        previewField.textColor = .tertiaryLabelColor
        previewField.preferredMaxLayoutWidth = 388
        stack.addArrangedSubview(previewField)

        scroll.documentView = stack

        // Calculate the needed height
        stack.layoutSubtreeIfNeeded()
        let fittingSize = stack.fittingSize
        let height = min(fittingSize.height + 8, 500)
        container.frame = NSRect(x: 0, y: 0, width: 420, height: height)
        scroll.frame = container.bounds

        self.view = container
        self.preferredContentSize = NSSize(width: 420, height: height)
    }

    private func addSection(to stack: NSStackView, title: String, items: [Finding], showReason: Bool) {
        let sectionTitle = NSTextField(labelWithString: title)
        sectionTitle.font = .systemFont(ofSize: 12, weight: .medium)
        sectionTitle.textColor = .labelColor
        stack.addArrangedSubview(sectionTitle)

        for item in items {
            let countStr = item.count > 1 ? "×\(item.count)  " : ""
            let reasonStr = showReason ? "  — \(item.reason)" : ""
            let line = NSTextField(labelWithString: "    \(countStr)\(item.name)\(reasonStr)")
            line.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            line.textColor = .secondaryLabelColor
            stack.addArrangedSubview(line)
        }
    }
}


// MARK: - Menu Bar App

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var hotKeyRef: EventHotKeyRef?
    var popover = NSPopover()
    let scanner = SlopScanner()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Menu bar
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = " slop"
            button.font = .monospacedSystemFont(ofSize: 12, weight: .medium)
            button.action = #selector(toggleMenu)
            button.target = self
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Scan Selected Text  ⌘⇧D", action: #selector(scanSelected), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Scan Clipboard", action: #selector(scanFromClipboard), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
        statusItem.menu = menu

        popover.behavior = .transient
        popover.animates = true

        registerHotKey()

        // Startup notification
        let n = NSUserNotification()
        n.title = "Slop Detector"
        n.informativeText = "Running. Press ⌘⇧D with text selected."
        NSUserNotificationCenter.default.deliver(n)
    }

    func registerHotKey() {
        var hotKeyID = EventHotKeyID()
        hotKeyID.signature = OSType(0x534C4F50)  // 'SLOP'
        hotKeyID.id = 1

        let modifiers: UInt32 = UInt32(cmdKey | shiftKey)
        let keyCode: UInt32 = 2  // 'D'

        var eventType = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )

        let handler: EventHandlerUPP = { _, event, _ -> OSStatus in
            let app = NSApplication.shared.delegate as! AppDelegate
            DispatchQueue.main.async { app.scanSelected() }
            return noErr
        }

        InstallEventHandler(GetApplicationEventTarget(), handler, 1, &eventType, nil, nil)
        RegisterEventHotKey(keyCode, modifiers, hotKeyID, GetApplicationEventTarget(), 0, &hotKeyRef)
    }

    @objc func toggleMenu() {}

    @objc func scanSelected() {
        let pasteboard = NSPasteboard.general
        let savedChangeCount = pasteboard.changeCount

        // Simulate Cmd+C
        let source = CGEventSource(stateID: .combinedSessionState)
        let cDown = CGEvent(keyboardEventSource: source, virtualKey: 0x08, keyDown: true)
        let cUp = CGEvent(keyboardEventSource: source, virtualKey: 0x08, keyDown: false)
        cDown?.flags = CGEventFlags.maskCommand
        cUp?.flags = CGEventFlags.maskCommand
        cDown?.post(tap: .cgSessionEventTap)
        cUp?.post(tap: .cgSessionEventTap)

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            guard let self = self else { return }

            // Only read if clipboard actually changed
            if pasteboard.changeCount != savedChangeCount,
               let text = pasteboard.string(forType: .string), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                self.runScan(text)
            } else if let text = pasteboard.string(forType: .string), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                // Clipboard didn't change but has content — scan what's there
                self.runScan(text)
            } else {
                let n = NSUserNotification()
                n.title = "Slop Detector"
                n.informativeText = "No text selected. Highlight text first."
                NSUserNotificationCenter.default.deliver(n)
            }
        }
    }

    @objc func scanFromClipboard() {
        if let text = NSPasteboard.general.string(forType: .string),
           !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            runScan(text)
        }
    }

    func runScan(_ text: String) {
        let result = scanner.scan(text)
        let formatted = formatResult(result, text: text)

        // Console output
        print(formatted.console)

        // Show popover from menu bar icon
        popover.contentViewController = ResultViewController(result: result, text: text)
        if let button = statusItem.button {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    @objc func quit() {
        NSApplication.shared.terminate(nil)
    }
}


// MARK: - Entry Point

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate

// Handle NSUserNotification delegate
class NotificationDelegate: NSObject, NSUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: NSUserNotificationCenter, shouldPresent notification: NSUserNotification) -> Bool { true }
}
let notifDelegate = NotificationDelegate()
NSUserNotificationCenter.default.delegate = notifDelegate

app.run()
