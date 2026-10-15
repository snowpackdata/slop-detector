import Cocoa
import Carbon

// MARK: - Sensitivity

enum Sensitivity: Int, CaseIterable {
    case low = 0, medium, high, max

    static func < (lhs: Sensitivity, rhs: Sensitivity) -> Bool { lhs.rawValue < rhs.rawValue }
    static func >= (lhs: Sensitivity, rhs: Sensitivity) -> Bool { lhs.rawValue >= rhs.rawValue }

    var label: String {
        switch self {
        case .low:    return "Low — obvious slop only"
        case .medium: return "Medium"
        case .high:   return "High"
        case .max:    return "Max — flag everything"
        }
    }

    var menuLabel: String {
        switch self {
        case .low: return "Low"; case .medium: return "Medium"
        case .high: return "High"; case .max: return "Max"
        }
    }

    var invisibleUnicode: Bool { true }
    var aiPunctuation: Bool { self >= .medium }
    var corePhrases: Bool { true }
    var extendedPhrases: Bool { self >= .medium }
    var statisticalAnalysis: Bool { self >= .high }

    var uniformityThreshold: Double {
        switch self { case .high: return 0.65; case .max: return 0.50; default: return 1.0 }
    }
    var vocabThreshold: Double {
        switch self { case .high: return 0.55; case .max: return 0.45; default: return 1.0 }
    }
    var hedgeThreshold: Double {
        switch self { case .high: return 0.020; case .max: return 0.012; default: return 1.0 }
    }
    var transitionThreshold: Double {
        switch self { case .high: return 0.010; case .max: return 0.006; default: return 1.0 }
    }
    var burstinessThreshold: Double {
        switch self { case .high: return 0.08; case .max: return 0.12; default: return 0.0 }
    }
    var openingRepetitionThreshold: Double {
        switch self { case .high: return 0.45; case .max: return 0.35; default: return 1.0 }
    }
}


// MARK: - Detection Data Types

struct Finding {
    enum Severity: String, Comparable {
        case info, warning, alert
        static func < (lhs: Severity, rhs: Severity) -> Bool {
            let order: [Severity] = [.info, .warning, .alert]
            return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
        }
    }
    enum Category: String {
        case unicode, punctuation, phrase, statistical, grammar, watermark
    }
    let severity: Severity
    let category: Category
    let name: String
    let reason: String
    let count: Int

    // Weight for scoring — how much this finding contributes to AI %
    var scoreWeight: Double {
        switch category {
        case .watermark:    return 25.0
        case .unicode:      return 10.0
        case .grammar:      return 6.0
        case .phrase:       return 5.0
        case .statistical:  return 4.0
        case .punctuation:  return 1.5
        }
    }
}

/// Per-chunk scan result
struct ChunkResult {
    let text: String
    let findings: [Finding]
    let wordCount: Int
    let score: Double  // 0-100 AI likelihood

    var verdict: String {
        switch score {
        case 0..<15:  return "Human"
        case 15..<35: return "Mostly human"
        case 35..<55: return "Mixed"
        case 55..<75: return "Likely AI"
        default:      return "AI"
        }
    }

    var color: NSColor {
        switch score {
        case 0..<15:  return .systemGreen
        case 15..<35: return NSColor(red: 0.4, green: 0.7, blue: 0.2, alpha: 1)
        case 35..<55: return .systemYellow
        case 55..<75: return .systemOrange
        default:      return .systemRed
        }
    }
}

/// Full document result with per-chunk breakdown
struct DocumentResult {
    let chunks: [ChunkResult]
    let overallScore: Double  // 0-100 weighted by chunk word count
    let sensitivity: Sensitivity
    let totalWordCount: Int
    let allFindings: [Finding]  // merged from all chunks

    var verdict: String {
        switch overallScore {
        case 0..<15:  return "Human"
        case 15..<35: return "Mostly human"
        case 35..<55: return "Mixed"
        case 55..<75: return "Likely AI"
        default:      return "AI"
        }
    }

    var overallColor: NSColor {
        switch overallScore {
        case 0..<15:  return .systemGreen
        case 15..<35: return NSColor(red: 0.4, green: 0.7, blue: 0.2, alpha: 1)
        case 35..<55: return .systemYellow
        case 55..<75: return .systemOrange
        default:      return .systemRed
        }
    }

    var aiChunkCount: Int { chunks.filter { $0.score >= 50 }.count }
    var humanChunkCount: Int { chunks.filter { $0.score < 50 }.count }
}


// MARK: - Detection Engine

class SlopScanner {

    // ── Unicode rules ─────────────────────────────────────────────────
    struct CharRule {
        let scalar: UInt32
        let name: String
        let severity: Finding.Severity
    }

    static let charRules: [CharRule] = [
        CharRule(scalar: 0x200B, name: "ZERO WIDTH SPACE", severity: .warning),
        CharRule(scalar: 0x200C, name: "ZERO WIDTH NON-JOINER", severity: .warning),
        CharRule(scalar: 0x200D, name: "ZERO WIDTH JOINER", severity: .warning),
        CharRule(scalar: 0x200E, name: "LEFT-TO-RIGHT MARK", severity: .warning),
        CharRule(scalar: 0x200F, name: "RIGHT-TO-LEFT MARK", severity: .warning),
        CharRule(scalar: 0x2060, name: "WORD JOINER", severity: .warning),
        CharRule(scalar: 0xFEFF, name: "BOM", severity: .warning),
        CharRule(scalar: 0x00AD, name: "SOFT HYPHEN", severity: .warning),
        CharRule(scalar: 0x00A0, name: "NO-BREAK SPACE", severity: .warning),
        CharRule(scalar: 0x202F, name: "NARROW NO-BREAK SPACE", severity: .warning),
        CharRule(scalar: 0x202A, name: "LTR EMBEDDING", severity: .warning),
        CharRule(scalar: 0x202B, name: "RTL EMBEDDING", severity: .warning),
        CharRule(scalar: 0x202C, name: "POP DIRECTIONAL", severity: .warning),
        CharRule(scalar: 0x202D, name: "LTR OVERRIDE", severity: .warning),
        CharRule(scalar: 0x202E, name: "RTL OVERRIDE", severity: .warning),
        CharRule(scalar: 0x2066, name: "LTR ISOLATE", severity: .warning),
        CharRule(scalar: 0x2067, name: "RTL ISOLATE", severity: .warning),
        CharRule(scalar: 0x2068, name: "FIRST STRONG ISOLATE", severity: .warning),
        CharRule(scalar: 0x2069, name: "POP DIRECTIONAL ISOLATE", severity: .warning),
        CharRule(scalar: 0x180E, name: "MONGOLIAN VOWEL SEP", severity: .warning),
        CharRule(scalar: 0x1160, name: "HANGUL FILLER", severity: .warning),
        CharRule(scalar: 0x3164, name: "HANGUL FILLER", severity: .warning),
        CharRule(scalar: 0x2028, name: "LINE SEPARATOR", severity: .warning),
        CharRule(scalar: 0x2029, name: "PARAGRAPH SEPARATOR", severity: .warning),
    ]

    static let punctuationRules: [CharRule] = [
        CharRule(scalar: 0x2014, name: "EM DASH", severity: .info),
        CharRule(scalar: 0x2013, name: "EN DASH", severity: .info),
        CharRule(scalar: 0x2026, name: "HORIZONTAL ELLIPSIS", severity: .info),
        CharRule(scalar: 0x201C, name: "LEFT DOUBLE QUOTE", severity: .info),
        CharRule(scalar: 0x201D, name: "RIGHT DOUBLE QUOTE", severity: .info),
        CharRule(scalar: 0x2018, name: "LEFT SINGLE QUOTE", severity: .info),
        CharRule(scalar: 0x2019, name: "RIGHT SINGLE QUOTE", severity: .info),
    ]

    // ── Phrase rules ──────────────────────────────────────────────────
    struct PhraseRule {
        let regex: NSRegularExpression
        let reason: String
        let core: Bool
    }

    static let phraseRules: [PhraseRule] = {
        let raw: [(String, String, Bool)] = [
            // Core (always on)
            (#"\bdelve(s|d|ing)?\b"#, "LLM filler", true),
            (#"\btapestry of\b"#, "LLM filler", true),
            (#"\brich tapestry\b"#, "LLM filler", true),
            (#"\bin the ever[- ]evolving landscape\b"#, "LLM cliché", true),
            (#"\bin today'?s fast[- ]paced world\b"#, "LLM cliché", true),
            (#"\bin today'?s digital\b"#, "LLM cliché", true),
            (#"\bin today'?s rapidly\b"#, "LLM cliché", true),
            (#"\bnavigate the complexit(y|ies)\b"#, "LLM cliché", true),
            (#"\ba testament to\b"#, "LLM filler", true),
            (#"\bembark(s|ed|ing)? on (a|this) journey\b"#, "LLM cliché", true),
            (#"\bmultifaceted\b"#, "LLM filler", true),
            (#"\bbustling\b"#, "LLM filler", true),
            (#"\bparadigm shift\b"#, "buzzword", true),
            (#"\bi hope this (helps|email finds you)\b"#, "LLM greeting", true),
            (#"\bi'?d be happy to help\b"#, "LLM greeting", true),
            (#"\bdon'?t hesitate to reach out\b"#, "LLM sign-off", true),
            (#"\bplease don'?t hesitate\b"#, "LLM sign-off", true),
            (#"\bsymphony of\b"#, "LLM cliché", true),
            (#"\blet'?s (dive|unpack)\b"#, "LLM structure", true),
            (#"\bhere'?s a breakdown\b"#, "LLM structure", true),
            (#"\blet me break this down\b"#, "LLM structure", true),
            (#"\bgreat question\b"#, "LLM filler", true),
            (#"\bhappy to discuss further\b"#, "LLM sign-off", true),

            // Extended (Medium+)
            (#"\bit'?s worth noting\b"#, "LLM hedge", false),
            (#"\bit'?s important to note\b"#, "LLM hedge", false),
            (#"\bat the heart of\b"#, "LLM filler", false),
            (#"\bcrucial role\b"#, "LLM filler", false),
            (#"\bplay(s|ed|ing)? a (crucial|pivotal|key|vital) role\b"#, "LLM filler", false),
            (#"\bharness(es|ed|ing)? the power of\b"#, "LLM filler", false),
            (#"\bunlock(s|ed|ing)? the (potential|power|secrets)\b"#, "LLM filler", false),
            (#"\bleverag(e|es|ed|ing)\b"#, "corporate-speak", false),
            (#"\brealm of\b"#, "LLM filler", false),
            (#"\bmeticulous(ly)?\b"#, "LLM filler", false),
            (#"\bunderscore(s|d)?\b"#, "LLM filler", false),
            (#"\bparamount\b"#, "LLM filler", false),
            (#"\bdive (in|into|deeper)\b"#, "LLM filler", false),
            (#"\bin conclusion,\b"#, "LLM structure", false),
            (#"\bwhen it comes to\b"#, "LLM filler", false),
            (#"\bthat said,\b"#, "LLM hedge", false),
            (#"\bhowever, it'?s\b"#, "LLM hedge", false),
            (#"\boverall,\b"#, "LLM structure", false),
            (#"\bultimately,\b"#, "LLM structure", false),
            (#"\bfoster(s|ed|ing)?\b"#, "LLM filler", false),
            (#"\bgame[- ]chang(er|ing)\b"#, "buzzword", false),
            (#"\bcutting[- ]edge\b"#, "buzzword", false),
            (#"\bstate[- ]of[- ]the[- ]art\b"#, "buzzword", false),
            (#"\brevolutioniz(e|es|ed|ing)\b"#, "LLM filler", false),
            (#"\bseamless(ly)?\b"#, "LLM filler", false),
            (#"\brobust\b"#, "LLM filler", false),
            (#"\bholistic\b"#, "LLM filler", false),
            (#"\bsynerg(y|ies|istic)\b"#, "corporate-speak", false),
            (#"\bcaptivating\b"#, "LLM cliché", false),
            (#"\besteemed\b"#, "LLM cliché", false),
            (#"\bexquisite\b"#, "LLM cliché", false),
            (#"\bpioneering\b"#, "LLM cliché", false),
            (#"\bprofound(ly)?\b"#, "LLM cliché", false),
            (#"\bprominent(ly)?\b"#, "LLM cliché", false),
            (#"\bquintessential\b"#, "LLM cliché", false),
            (#"\btrailblazing\b"#, "LLM cliché", false),
            (#"\bunwavering\b"#, "LLM cliché", false),
            (#"\bvisionary\b"#, "LLM cliché", false),
            (#"\bepitome\b"#, "LLM cliché", false),
            (#"\bpinnacle\b"#, "LLM cliché", false),
            (#"\benvision(s|ed|ing)?\b"#, "LLM cliché", false),
            (#"\btranscend(s|ed|ing)?\b"#, "LLM cliché", false),
            (#"\bunleash(es|ed|ing)?\b"#, "LLM cliché", false),
            (#"\blandscape of\b"#, "LLM cliché", false),
            (#"\bspectrum of\b"#, "LLM cliché", false),
            (#"\bcornerstone\b"#, "LLM filler", false),
            (#"\bpivotal\b"#, "LLM filler", false),
            (#"\bnuanced\b"#, "LLM filler", false),
            (#"\bcommendable\b"#, "LLM filler", false),
            (#"\bintricate(s|ly)?\b"#, "LLM filler", false),
            (#"\bintricacies\b"#, "LLM filler", false),
            (#"\bakin to\b"#, "LLM filler", false),
            (#"\bhenceforth\b"#, "LLM filler", false),
            (#"\bwhilst\b"#, "LLM filler", false),
            (#"\belevat(e|es|ed|ing)\b"#, "LLM filler", false),
            (#"\bspearhead(s|ed|ing)?\b"#, "LLM filler", false),
            (#"\bresonate(s)?\b"#, "LLM filler", false),
            (#"\bstreamlin(e|es|ed|ing)\b"#, "LLM filler", false),
            (#"\bempow(er|ers|ered|ering)\b"#, "LLM filler", false),
            (#"\bkey takeaways?\b"#, "LLM structure", false),
            (#"\bgalvaniz(e|es|ed|ing)\b"#, "LLM cliché", false),
            (#"\busher(s|ed|ing)? in\b"#, "LLM cliché", false),
            (#"\bindomitable\b"#, "LLM cliché", false),
            (#"\birrefutable\b"#, "LLM cliché", false),
            (#"\bomniscient\b"#, "LLM cliché", false),
            (#"\btangible\b"#, "LLM cliché", false),
            (#"\bubiquitous\b"#, "LLM cliché", false),
            (#"\bunyielding\b"#, "LLM cliché", false),
            (#"\bunassailable\b"#, "LLM cliché", false),
            (#"\bunsurpassed\b"#, "LLM cliché", false),
            (#"\bunrivaled\b"#, "LLM cliché", false),
            (#"\bfacet(s)?\b"#, "LLM cliché", false),
            (#"\btrajectory\b"#, "LLM cliché", false),
            (#"\bpanorama of\b"#, "LLM cliché", false),
            (#"\bredefin(e|es|ed|ing)\b"#, "LLM cliché", false),
            (#"\breinforc(e|es|ed|ing)\b"#, "LLM cliché", false),
            (#"\bthank you for (sharing|your (thoughtful|insightful|detailed))\b"#, "LLM greeting", false),
            (#"\bi appreciate you sharing\b"#, "LLM greeting", false),
            (#"\bthis is a (great|excellent|wonderful|fantastic) (question|point)\b"#, "LLM filler", false),
            (#"\babsolutely[!.]"#, "LLM filler", false),
            (#"\bI couldn'?t agree more\b"#, "LLM filler", false),
            (#"\byou'?re (absolutely |exactly )?right\b"#, "LLM filler", false),
            (#"\bthat'?s (a |an )?(excellent|great|fantastic|wonderful) (point|question|observation)\b"#, "LLM filler", false),
            (#"\b(crucially|importantly|notably|significantly|remarkably),\b"#, "LLM hedge", false),
            (#"\b(additionally|furthermore|moreover),\b"#, "LLM transition", false),
            (#"\bconsequently,\b"#, "LLM transition", false),
            (#"\bnevertheless,\b"#, "LLM transition", false),
            (#"\bnonetheless,\b"#, "LLM transition", false),
            (#"\bnotwithstanding\b"#, "LLM transition", false),
            (#"\bit'?s also (worth|important)\b"#, "LLM hedge", false),
            (#"\bthis (is a |)(complex|nuanced|multifaceted|important) (topic|issue|area|subject|question)\b"#, "LLM hedge", false),
            (#"\bwith that (being |)said\b"#, "LLM hedge", false),
            (#"\bhaving said that\b"#, "LLM hedge", false),
            (#"\b(ensure|ensures|ensuring) that\b"#, "LLM filler", false),
            (#"\bfeel free to\b"#, "LLM sign-off", false),
            (#"\blooking forward to\b"#, "LLM sign-off", false),
            (#"\bplease let me know if\b"#, "LLM sign-off", false),
            (#"\bI'?m here to help\b"#, "LLM sign-off", false),
        ]
        return raw.compactMap { (pattern, reason, core) in
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
            return PhraseRule(regex: regex, reason: reason, core: core)
        }
    }()

    // ── Word lists ────────────────────────────────────────────────────
    static let hedgeWords: Set<String> = [
        "generally", "typically", "usually", "often", "sometimes",
        "arguably", "perhaps", "possibly", "potentially", "likely",
        "seemingly", "apparently", "essentially", "fundamentally",
        "basically", "primarily", "largely", "mainly", "mostly",
        "virtually", "practically", "relatively", "somewhat",
        "fairly", "quite", "rather", "certainly", "undoubtedly",
        "inevitably", "inherently", "particularly", "especially",
        "specifically", "notably", "importantly", "significantly",
        "effectively", "ultimately", "accordingly",
    ]

    static let transitionWords: Set<String> = [
        "furthermore", "moreover", "additionally", "consequently",
        "nevertheless", "nonetheless", "henceforth", "thereby",
        "subsequently", "accordingly", "conversely", "notwithstanding",
        "hitherto", "heretofore", "aforementioned", "whereby",
        "insofar", "inasmuch", "therein", "thereof", "herein",
        "thus", "hence",
    ]

    static let productNames: Set<String> = [
        "fivetran", "airflow", "dbt", "snowflake", "bigquery", "redshift",
        "postgres", "postgresql", "mysql", "mongodb", "redis", "kafka",
        "elasticsearch", "docker", "kubernetes", "terraform", "jenkins",
        "github", "gitlab", "jira", "confluence", "slack", "stripe",
        "twilio", "sendgrid", "datadog", "grafana", "prometheus",
        "nginx", "apache", "webpack", "babel", "eslint", "prettier",
        "react", "angular", "vue", "nextjs", "vercel", "netlify",
        "aws", "gcp", "azure", "heroku", "railway",
        "segment", "amplitude", "mixpanel", "hubspot", "salesforce",
        "gusto", "rippling", "looker", "tableau", "metabase",
        "sentry", "pagerduty", "opsgenie", "circleci",
        "npm", "yarn", "pip", "cargo", "maven", "gradle",
        "celery", "sidekiq", "resque", "bull",
    ]

    // ── Chunked document scan ─────────────────────────────────────────
    func scanDocument(_ text: String, sensitivity: Sensitivity) -> DocumentResult {
        let chunks = splitIntoChunks(text)

        // If text is very short (one chunk, few words), just scan as-is
        if chunks.count == 1 {
            let result = scanChunk(chunks[0], sensitivity: sensitivity)
            return DocumentResult(
                chunks: [result],
                overallScore: result.score,
                sensitivity: sensitivity,
                totalWordCount: result.wordCount,
                allFindings: result.findings
            )
        }

        // Score each chunk independently
        let chunkResults = chunks.map { scanChunk($0, sensitivity: sensitivity) }

        // Weighted average by word count
        let totalWords = chunkResults.reduce(0) { $0 + $1.wordCount }
        let weightedScore: Double
        if totalWords > 0 {
            weightedScore = chunkResults.reduce(0.0) {
                $0 + $1.score * Double($1.wordCount)
            } / Double(totalWords)
        } else {
            weightedScore = 0
        }

        // Merge findings (deduplicate by name, sum counts)
        var findingMap: [String: Finding] = [:]
        for chunk in chunkResults {
            for f in chunk.findings {
                if let existing = findingMap[f.name] {
                    findingMap[f.name] = Finding(
                        severity: Swift.max(existing.severity, f.severity),
                        category: f.category,
                        name: f.name,
                        reason: f.reason,
                        count: existing.count + f.count
                    )
                } else {
                    findingMap[f.name] = f
                }
            }
        }
        let allFindings = Array(findingMap.values).sorted { $0.scoreWeight > $1.scoreWeight }

        return DocumentResult(
            chunks: chunkResults,
            overallScore: weightedScore,
            sensitivity: sensitivity,
            totalWordCount: totalWords,
            allFindings: allFindings
        )
    }

    // ── Split text into analyzable chunks ─────────────────────────────
    private func splitIntoChunks(_ text: String) -> [String] {
        // Split on paragraph boundaries (double newline or single newline with blank)
        let paragraphs = text
            .components(separatedBy: "\n\n")
            .flatMap { $0.components(separatedBy: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty } == [$0.trimmingCharacters(in: .whitespaces)] ? [$0] : $0.components(separatedBy: "\n") }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        // If we only got one chunk, try splitting on single newlines
        if paragraphs.count <= 1 {
            let lines = text.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if lines.count > 1 { return mergeSmallChunks(lines) }
        }

        return mergeSmallChunks(paragraphs)
    }

    // Merge chunks that are too small to score meaningfully (< 15 words)
    private func mergeSmallChunks(_ chunks: [String]) -> [String] {
        var result: [String] = []
        var buffer = ""

        for chunk in chunks {
            let words = chunk.split(separator: " ").count
            if buffer.isEmpty {
                if words < 15 {
                    buffer = chunk
                } else {
                    result.append(chunk)
                }
            } else {
                buffer += " " + chunk
                let bufferWords = buffer.split(separator: " ").count
                if bufferWords >= 15 {
                    result.append(buffer)
                    buffer = ""
                }
            }
        }
        if !buffer.isEmpty {
            if result.isEmpty {
                result.append(buffer)
            } else {
                result[result.count - 1] += " " + buffer
            }
        }
        return result
    }

    // ── Score a single chunk ──────────────────────────────────────────
    func scanChunk(_ text: String, sensitivity: Sensitivity) -> ChunkResult {
        var findings: [Finding] = []
        let words = tokenize(text)
        let wordCount = words.count

        guard wordCount >= 5 else {
            return ChunkResult(text: text, findings: [], wordCount: wordCount, score: 0)
        }

        // 1. Invisible Unicode
        if sensitivity.invisibleUnicode {
            findings += scanChars(text, rules: SlopScanner.charRules, category: .unicode)
        }

        // 2. AI punctuation
        if sensitivity.aiPunctuation {
            findings += scanChars(text, rules: SlopScanner.punctuationRules, category: .punctuation)
        }

        // 3. Phrases
        let nsText = text as NSString
        let fullRange = NSRange(location: 0, length: nsText.length)
        for rule in SlopScanner.phraseRules {
            if !rule.core && !sensitivity.extendedPhrases { continue }
            let matches = rule.regex.matches(in: text, range: fullRange)
            if !matches.isEmpty {
                let firstMatch = nsText.substring(with: matches[0].range)
                findings.append(Finding(
                    severity: .info, category: .phrase,
                    name: "\"\(firstMatch)\"", reason: rule.reason,
                    count: matches.count
                ))
            }
        }

        // 4. Statistical
        if sensitivity.statisticalAnalysis && wordCount >= 30 {
            findings += statisticalAnalysis(text, words: words, sensitivity: sensitivity)
        }

        // 5. Grammar
        if sensitivity.extendedPhrases && wordCount >= 20 {
            findings += grammarAnalysis(text, sensitivity: sensitivity)
        }

        // 6. Watermarks
        findings += watermarkDetection(text)

        // Compute score: weighted sum of findings, normalized by word count
        let rawScore = findings.reduce(0.0) { total, f in
            total + f.scoreWeight * Double(f.count)
        }
        // Normalize: more findings per word = higher score
        // A 50-word chunk with 3 phrase hits and 2 grammar flags should score ~60-70%
        let density = rawScore / Double(max(wordCount, 1)) * 8.0
        let score = min(100.0, max(0.0, density))

        return ChunkResult(text: text, findings: findings, wordCount: wordCount, score: score)
    }

    // ── Character scanning ────────────────────────────────────────────
    private func scanChars(_ text: String, rules: [CharRule], category: Finding.Category) -> [Finding] {
        var scalarCounts: [UInt32: Int] = [:]
        for scalar in text.unicodeScalars {
            scalarCounts[scalar.value, default: 0] += 1
        }
        var findings: [Finding] = []
        for rule in rules {
            if let count = scalarCounts[rule.scalar], count > 0 {
                let reason = category == .unicode ? "invisible/suspicious Unicode" : "AI-style punctuation"
                findings.append(Finding(
                    severity: rule.severity, category: category,
                    name: rule.name, reason: reason, count: count
                ))
            }
        }
        return findings
    }

    // ── Statistical analysis ──────────────────────────────────────────
    private func statisticalAnalysis(_ text: String, words: [String], sensitivity: Sensitivity) -> [Finding] {
        var findings: [Finding] = []
        let sentences = splitSentences(text)
        let lowerWords = words.map { $0.lowercased() }

        // Sentence length uniformity
        if sentences.count >= 4 {
            let lengths = sentences.map { Double(tokenize($0).count) }
            let mean = lengths.reduce(0, +) / Double(lengths.count)
            if mean > 0 {
                let variance = lengths.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(lengths.count)
                let cv = sqrt(variance) / mean
                if cv < sensitivity.uniformityThreshold {
                    let pct = Int((1.0 - cv / 0.7) * 100)
                    findings.append(Finding(
                        severity: .info, category: .statistical,
                        name: "Sentence uniformity \(pct)%",
                        reason: "Unusually even sentence lengths (CV=\(String(format: "%.2f", cv)))",
                        count: 1
                    ))
                }
            }
        }

        // Vocabulary diversity
        if words.count >= 40 {
            let unique = Set(lowerWords)
            let ttr = Double(unique.count) / Double(lowerWords.count)
            let normalizedTTR = ttr * sqrt(Double(words.count) / 100.0)
            if normalizedTTR < sensitivity.vocabThreshold {
                let pct = Int((1.0 - normalizedTTR / 0.7) * 100)
                findings.append(Finding(
                    severity: .info, category: .statistical,
                    name: "Low vocabulary diversity \(pct)%",
                    reason: "Repetitive word choices (TTR=\(String(format: "%.2f", ttr)))",
                    count: 1
                ))
            }
        }

        // Hedge word density
        let hedgeCount = lowerWords.filter { SlopScanner.hedgeWords.contains($0) }.count
        let hedgeDensity = Double(hedgeCount) / Double(max(words.count, 1))
        if hedgeDensity > sensitivity.hedgeThreshold {
            let pct = String(format: "%.1f", hedgeDensity * 100)
            findings.append(Finding(
                severity: .info, category: .statistical,
                name: "Hedge word density \(pct)%",
                reason: "\(hedgeCount) hedge words in \(words.count) words",
                count: hedgeCount
            ))
        }

        // Transition density
        let transCount = lowerWords.filter { SlopScanner.transitionWords.contains($0) }.count
        let transDensity = Double(transCount) / Double(max(words.count, 1))
        if transDensity > sensitivity.transitionThreshold {
            let pct = String(format: "%.1f", transDensity * 100)
            findings.append(Finding(
                severity: .info, category: .statistical,
                name: "Formal transition density \(pct)%",
                reason: "\(transCount) formal transitions in \(words.count) words",
                count: transCount
            ))
        }

        // Burstiness
        if sentences.count >= 4 {
            let avgWordLens = sentences.map { sent -> Double in
                let w = tokenize(sent)
                guard !w.isEmpty else { return 0 }
                return w.map { Double($0.count) }.reduce(0, +) / Double(w.count)
            }.filter { $0 > 0 }
            if avgWordLens.count >= 3 {
                let mean = avgWordLens.reduce(0, +) / Double(avgWordLens.count)
                if mean > 0 {
                    let variance = avgWordLens.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(avgWordLens.count)
                    let cv = sqrt(variance) / mean
                    if cv < sensitivity.burstinessThreshold {
                        findings.append(Finding(
                            severity: .info, category: .statistical,
                            name: "Low burstiness",
                            reason: "Flat sentence complexity (CV=\(String(format: "%.2f", cv)))",
                            count: 1
                        ))
                    }
                }
            }
        }

        // Repetitive openings
        if sentences.count >= 5 {
            var openingWords: [String: Int] = [:]
            for sent in sentences {
                let firstWord = tokenize(sent).first?.lowercased() ?? ""
                if !firstWord.isEmpty { openingWords[firstWord, default: 0] += 1 }
            }
            let maxRepeat = openingWords.values.max() ?? 0
            let repeatRatio = Double(maxRepeat) / Double(sentences.count)
            if repeatRatio > sensitivity.openingRepetitionThreshold {
                let word = openingWords.max(by: { $0.value < $1.value })?.key ?? "?"
                findings.append(Finding(
                    severity: .info, category: .statistical,
                    name: "Repetitive openings",
                    reason: "\(maxRepeat)/\(sentences.count) sentences start with \"\(word)\"",
                    count: maxRepeat
                ))
            }
        }

        // List structure
        let lines = text.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        if lines.count >= 4 {
            var listCount = 0
            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("- ") || trimmed.hasPrefix("• ") || trimmed.hasPrefix("* ") {
                    listCount += 1
                } else if let first = trimmed.first, first.isNumber {
                    let afterNum = trimmed.drop(while: { $0.isNumber })
                    if afterNum.hasPrefix(". ") || afterNum.hasPrefix(") ") { listCount += 1 }
                }
            }
            let listRatio = Double(listCount) / Double(lines.count)
            if listRatio > 0.4 {
                findings.append(Finding(
                    severity: .info, category: .statistical,
                    name: "Heavy list structure",
                    reason: "\(listCount)/\(lines.count) lines are list items",
                    count: listCount
                ))
            }
        }

        // Adverb density
        if words.count >= 30 {
            let adverbCount = lowerWords.filter { $0.hasSuffix("ly") && $0.count > 3 }.count
            let adverbDensity = Double(adverbCount) / Double(words.count)
            let threshold = sensitivity == .max ? 0.035 : 0.045
            if adverbDensity > threshold {
                let pct = String(format: "%.1f", adverbDensity * 100)
                findings.append(Finding(
                    severity: .info, category: .statistical,
                    name: "Adverb density \(pct)%",
                    reason: "\(adverbCount) -ly adverbs in \(words.count) words",
                    count: adverbCount
                ))
            }
        }

        return findings
    }

    // ── Grammar analysis ──────────────────────────────────────────────
    private func grammarAnalysis(_ text: String, sensitivity: Sensitivity) -> [Finding] {
        var findings: [Finding] = []
        let sentences = splitSentences(text)
        guard sentences.count >= 3 else { return findings }

        let passiveRegex = try! NSRegularExpression(
            pattern: #"\b(is|are|was|were|been|being|get|gets|got|gotten)\s+(being\s+)?([\w]+ed|[\w]+en|built|made|done|seen|known|given|taken|found|thought|held|run|set|put|kept|brought|shown|told|left|said|meant|understood|written|chosen|driven|spoken|broken|forgotten|hidden|risen|fallen|drawn|worn|torn|sworn|grown|thrown|blown|flown|shaken|mistaken|forsaken)\b"#,
            options: [.caseInsensitive]
        )
        let itIsRegex = try! NSRegularExpression(
            pattern: #"^(it is|it's|it was|it has been|it can be|it should be|it could be|it would be|it may be|it might be)\b"#,
            options: [.caseInsensitive]
        )
        let thereAreRegex = try! NSRegularExpression(
            pattern: #"^(there is|there's|there are|there were|there was|there have been|there has been|there exist)\b"#,
            options: [.caseInsensitive]
        )
        let gerundSubjectRegex = try! NSRegularExpression(
            pattern: #"^(understanding|implementing|leveraging|utilizing|navigating|ensuring|addressing|creating|building|developing|establishing|maintaining|considering|examining|exploring|incorporating|integrating|optimizing|streamlining|fostering|facilitating|harnessing|embracing)\b"#,
            options: [.caseInsensitive]
        )
        let thisIsRegex = try! NSRegularExpression(
            pattern: #"^this (is|represents|allows|enables|ensures|provides|creates|highlights|demonstrates|illustrates|shows|means|suggests|indicates|reflects|involves|includes|requires|offers|serves)\b"#,
            options: [.caseInsensitive]
        )
        let droppedSubjectRegex = try! NSRegularExpression(
            pattern: #"^(Works|Runs|Returns|Handles|Sends|Takes|Makes|Gives|Gets|Keeps|Puts|Sets|Lets|Adds|Uses|Calls|Creates|Builds|Reads|Writes|Checks|Parses|Loads|Stores|Fetches|Pulls|Pushes|Passes|Maps|Converts|Transforms|Wraps|Strips|Splits|Joins|Merges|Triggers|Fires|Emits|Throws|Catches|Logs|Tracks|Counts|Finds|Looks|Grabs|Drops|Skips|Falls|Sits|Helps|Allows|Enables|Ensures|Provides|Supports|Includes|Contains|Represents|Defines|Specifies|Indicates|Shows|Displays|Renders|Formats|Applies|Accepts|Receives|Validates|Prevents|Avoids|Ignores|Defaults|Assumes|Expects|Requires|Needs|Depends|Connects|Points|Refers|Links)\b"#,
            options: []
        )
        let personificationRegex = try! NSRegularExpression(
            pattern: #"(?:^|[.!?]\s+)(?:The |the |)([A-Z][a-zA-Z]*(?:\s[A-Z][a-zA-Z]*)?)\s+(knows?|sees?|thinks?|believes?|decides?|wants?|has|have|had|realizes?|recognizes?|understands?|determines?|identifies?|considers?|expects?|assumes?|remembers?|forgets?|learns?|notices?|discovers?|figures?|feels?|cares?|minds?|worries|prefers?|chooses?|picks?|likes?|hates?|loves?|enjoys?|watches?|listens?|tells?|says?|speaks?|asks?|answers?|names?|calls?)\b"#,
            options: []
        )
        let abstractionRegex = try! NSRegularExpression(
            pattern: #"\b(the\s+)(config|configuration|pipeline|workflow|endpoint|API|UTM|URL|query|schema|migration|cron|job|script|function|method|module|package|library|framework|service|server|database|cache|queue|proxy|gateway|router|middleware|handler|controller|scheduler|daemon|container|cluster|pod|node|bucket|table|column|field|index|view|model|template|plugin|extension|hook|trigger|webhook|listener|worker|task|process|thread|runtime|compiler|parser|linter|formatter|bundler|loader|resolver|adapter|connector|driver|client|provider|factory|wrapper|helper|utility|manager|registry|store|repository|broker|monitor|logger|profiler|debugger|tracer|emitter|dispatcher|orchestrator|coordinator|aggregator|transformer|serializer|validator|sanitizer|normalizer|tokenizer|encoder|decoder|encryptor|compressor|buffer|stream|socket|channel|transport|protocol)\s+(knows?|sees?|thinks?|believes?|decides?|wants?|has|have|had|realizes?|recognizes?|understands?|determines?|identifies?|considers?|expects?|assumes?|remembers?|forgets?|learns?|notices?|discovers?|feels?|cares?|minds?|worries|prefers?|chooses?|names?|calls?|tells?|says?)\b"#,
            options: [.caseInsensitive]
        )

        let humanWords: Set<String> = ["i", "we", "you", "he", "she", "they", "it",
            "someone", "anyone", "everyone", "nobody", "people", "team", "user",
            "users", "client", "clients", "customer", "admin", "staff", "manager",
            "developer", "engineer", "analyst", "designer", "lead", "director"]

        var passiveCount = 0, itIsCount = 0, thereAreCount = 0
        var gerundSubjectCount = 0, thisIsCount = 0
        var droppedSubjectCount = 0, personificationCount = 0
        var droppedExamples: [String] = []
        var personExamples: [String] = []

        for sent in sentences {
            let nsSent = sent as NSString
            let range = NSRange(location: 0, length: nsSent.length)

            passiveCount += passiveRegex.numberOfMatches(in: sent, range: range)
            if itIsRegex.firstMatch(in: sent, range: range) != nil { itIsCount += 1 }
            if thereAreRegex.firstMatch(in: sent, range: range) != nil { thereAreCount += 1 }
            if gerundSubjectRegex.firstMatch(in: sent, range: range) != nil { gerundSubjectCount += 1 }
            if thisIsRegex.firstMatch(in: sent, range: range) != nil { thisIsCount += 1 }

            let trimmed = sent.trimmingCharacters(in: .whitespaces)
            let trimRange = NSRange(location: 0, length: (trimmed as NSString).length)
            if droppedSubjectRegex.firstMatch(in: trimmed, range: trimRange) != nil {
                droppedSubjectCount += 1
                if droppedExamples.count < 2 { droppedExamples.append(String(trimmed.prefix(50))) }
            }

            // Product personification
            for m in personificationRegex.matches(in: sent, range: range) {
                if m.numberOfRanges >= 2 {
                    let name = nsSent.substring(with: m.range(at: 1)).lowercased()
                    if !humanWords.contains(name) && SlopScanner.productNames.contains(name) {
                        personificationCount += 1
                        if personExamples.count < 2 { personExamples.append(String(sent.prefix(60))) }
                    }
                }
            }

            // Abstraction personification
            let aMatches = abstractionRegex.numberOfMatches(in: sent, range: range)
            if aMatches > 0 {
                personificationCount += aMatches
                if personExamples.count < 2 { personExamples.append(String(sent.prefix(60))) }
            }
        }

        let passiveRatio = Double(passiveCount) / Double(sentences.count)
        if passiveRatio > (sensitivity == .max ? 0.25 : 0.35) {
            findings.append(Finding(severity: .info, category: .grammar,
                name: "Passive voice \(Int(passiveRatio * 100))%",
                reason: "\(passiveCount)/\(sentences.count) sentences", count: passiveCount))
        }

        let impersonalCount = itIsCount + thereAreCount
        let impersonalRatio = Double(impersonalCount) / Double(sentences.count)
        if impersonalRatio > (sensitivity == .max ? 0.20 : 0.30) {
            findings.append(Finding(severity: .info, category: .grammar,
                name: "Impersonal openings \(Int(impersonalRatio * 100))%",
                reason: "\(impersonalCount) \"It is\"/\"There are\" starts", count: impersonalCount))
        }

        if gerundSubjectCount >= 2 {
            findings.append(Finding(severity: .info, category: .grammar,
                name: "Gerund subjects",
                reason: "\(gerundSubjectCount)× -ing as subject", count: gerundSubjectCount))
        }

        let thisIsRatio = Double(thisIsCount) / Double(sentences.count)
        if thisIsRatio > 0.20 {
            findings.append(Finding(severity: .info, category: .grammar,
                name: "\"This is/enables\" \(Int(thisIsRatio * 100))%",
                reason: "Vague \"this\" connector", count: thisIsCount))
        }

        if droppedSubjectCount >= 2 {
            let ex = droppedExamples.map { "\"\($0)…\"" }.joined(separator: ", ")
            findings.append(Finding(severity: .info, category: .grammar,
                name: "Dropped subjects (\(droppedSubjectCount)×)",
                reason: "No actor — \(ex)", count: droppedSubjectCount))
        }

        if personificationCount >= 1 {
            let ex = personExamples.map { "\"\($0)…\"" }.joined(separator: "; ")
            findings.append(Finding(severity: .info, category: .grammar,
                name: "Tool personification (\(personificationCount)×)",
                reason: "Gives agency to software — \(ex)", count: personificationCount))
        }

        // First-person avoidance
        let words = tokenize(text)
        let lowerWords = words.map { $0.lowercased() }
        let iCount = lowerWords.filter { $0 == "i" || $0 == "i'm" || $0 == "i've" || $0 == "i'd" || $0 == "i'll" || $0 == "my" || $0 == "me" }.count
        if words.count >= 60 && Double(iCount) / Double(words.count) < 0.005 && sentences.count >= 5 {
            findings.append(Finding(severity: .info, category: .grammar,
                name: "No first-person voice",
                reason: "Long text with no I/me/my", count: 1))
        }

        return findings
    }

    // ── Watermark detection ───────────────────────────────────────────
    private func watermarkDetection(_ text: String) -> [Finding] {
        var findings: [Finding] = []
        struct HomoglyphCheck { let name: String; let scalars: [UInt32] }

        let homoglyphs: [HomoglyphCheck] = [
            HomoglyphCheck(name: "Cyrillic 'a'", scalars: [0x0430]),
            HomoglyphCheck(name: "Cyrillic 'c'", scalars: [0x0441]),
            HomoglyphCheck(name: "Cyrillic 'e'", scalars: [0x0435]),
            HomoglyphCheck(name: "Cyrillic 'o'", scalars: [0x043E]),
            HomoglyphCheck(name: "Cyrillic 'p'", scalars: [0x0440]),
            HomoglyphCheck(name: "Cyrillic 'x'", scalars: [0x0445]),
            HomoglyphCheck(name: "Cyrillic 'y'", scalars: [0x0443]),
            HomoglyphCheck(name: "Cyrillic caps", scalars: [0x0410, 0x0412, 0x0421, 0x0415, 0x041D, 0x041A, 0x041C, 0x041E, 0x0420, 0x0422, 0x0425]),
            HomoglyphCheck(name: "Greek lookalikes", scalars: [0x03BF, 0x03B1]),
            HomoglyphCheck(name: "Variation selectors", scalars: Array(0xFE00...0xFE0F)),
            HomoglyphCheck(name: "Tag characters", scalars: Array(0xE0001...0xE007F)),
            HomoglyphCheck(name: "Interlinear annotation", scalars: [0xFFF9, 0xFFFA, 0xFFFB]),
        ]

        var scalarCounts: [UInt32: Int] = [:]
        for scalar in text.unicodeScalars { scalarCounts[scalar.value, default: 0] += 1 }

        var hits: [(String, Int)] = []
        for check in homoglyphs {
            let total = check.scalars.reduce(0) { $0 + (scalarCounts[$1] ?? 0) }
            if total > 0 { hits.append((check.name, total)) }
        }

        if !hits.isEmpty {
            let totalCount = hits.reduce(0) { $0 + $1.1 }
            let desc = hits.map { "\($0.0) ×\($0.1)" }.joined(separator: ", ")
            findings.append(Finding(
                severity: .alert, category: .watermark,
                name: "Unicode watermark/homoglyphs",
                reason: "\(totalCount) non-ASCII substitutions: \(desc)", count: totalCount
            ))
        }

        let lines = text.components(separatedBy: .newlines)
        var trailingWS = 0
        for line in lines where !line.isEmpty {
            if let last = line.unicodeScalars.last, last == " " || last == "\t" { trailingWS += 1 }
        }
        let nonEmpty = lines.filter { !$0.isEmpty }.count
        if nonEmpty >= 3 && trailingWS > nonEmpty / 2 {
            findings.append(Finding(
                severity: .warning, category: .watermark,
                name: "Trailing whitespace pattern",
                reason: "\(trailingWS)/\(nonEmpty) lines", count: trailingWS
            ))
        }

        return findings
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private func tokenize(_ text: String) -> [String] {
        text.components(separatedBy: .whitespacesAndNewlines)
            .map { $0.trimmingCharacters(in: .punctuationCharacters) }
            .filter { !$0.isEmpty }
    }

    private func splitSentences(_ text: String) -> [String] {
        var sentences: [String] = []
        text.enumerateSubstrings(in: text.startIndex..., options: [.bySentences, .localized]) { sub, _, _, _ in
            if let s = sub?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty {
                sentences.append(s)
            }
        }
        return sentences.isEmpty ? [text] : sentences
    }
}


// MARK: - Popover Result View

class ResultViewController: NSViewController {
    let docResult: DocumentResult
    let scannedText: String

    init(docResult: DocumentResult, text: String) {
        self.docResult = docResult
        self.scannedText = text
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 10))

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
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)

        // ── Score header ──────────────────────────────────────────────
        let scorePct = Int(docResult.overallScore)
        let header = NSTextField(labelWithString: "\(scorePct)% AI")
        header.font = .systemFont(ofSize: 28, weight: .bold)
        header.textColor = docResult.overallColor
        stack.addArrangedSubview(header)

        let verdictLine = NSTextField(labelWithString: "\(docResult.verdict) · \(docResult.totalWordCount) words · \(docResult.sensitivity.menuLabel) sensitivity")
        verdictLine.font = .systemFont(ofSize: 11)
        verdictLine.textColor = .secondaryLabelColor
        stack.addArrangedSubview(verdictLine)

        // ── Score bar ─────────────────────────────────────────────────
        let barContainer = NSView()
        barContainer.translatesAutoresizingMaskIntoConstraints = false
        barContainer.wantsLayer = true
        barContainer.layer?.cornerRadius = 4
        barContainer.layer?.backgroundColor = NSColor.separatorColor.cgColor

        let barFill = NSView()
        barFill.translatesAutoresizingMaskIntoConstraints = false
        barFill.wantsLayer = true
        barFill.layer?.cornerRadius = 4
        barFill.layer?.backgroundColor = docResult.overallColor.cgColor

        barContainer.addSubview(barFill)
        stack.addArrangedSubview(barContainer)

        NSLayoutConstraint.activate([
            barContainer.widthAnchor.constraint(equalToConstant: 428),
            barContainer.heightAnchor.constraint(equalToConstant: 8),
            barFill.leadingAnchor.constraint(equalTo: barContainer.leadingAnchor),
            barFill.topAnchor.constraint(equalTo: barContainer.topAnchor),
            barFill.bottomAnchor.constraint(equalTo: barContainer.bottomAnchor),
            barFill.widthAnchor.constraint(equalTo: barContainer.widthAnchor, multiplier: CGFloat(min(1.0, max(0.0, docResult.overallScore / 100.0)))),
        ])

        // ── Per-chunk breakdown (if multiple chunks) ──────────────────
        if docResult.chunks.count > 1 {
            addSeparator(to: stack)

            let chunkHeader = NSTextField(labelWithString: "Per-paragraph breakdown (\(docResult.aiChunkCount) AI, \(docResult.humanChunkCount) human)")
            chunkHeader.font = .systemFont(ofSize: 12, weight: .medium)
            chunkHeader.textColor = .labelColor
            stack.addArrangedSubview(chunkHeader)

            for (i, chunk) in docResult.chunks.enumerated() {
                let chunkPct = Int(chunk.score)
                let preview = String(chunk.text.prefix(70)).replacingOccurrences(of: "\n", with: " ")
                let flagCount = chunk.findings.count

                let chunkView = NSView()
                chunkView.translatesAutoresizingMaskIntoConstraints = false

                // Color indicator dot
                let dot = NSView()
                dot.translatesAutoresizingMaskIntoConstraints = false
                dot.wantsLayer = true
                dot.layer?.cornerRadius = 4
                dot.layer?.backgroundColor = chunk.color.cgColor
                chunkView.addSubview(dot)

                let pctLabel = NSTextField(labelWithString: "\(chunkPct)%")
                pctLabel.font = .monospacedDigitSystemFont(ofSize: 11, weight: .medium)
                pctLabel.textColor = chunk.color
                pctLabel.translatesAutoresizingMaskIntoConstraints = false
                chunkView.addSubview(pctLabel)

                let textLabel = NSTextField(labelWithString: "\"\(preview)\(chunk.text.count > 70 ? "…" : "")\"")
                textLabel.font = .systemFont(ofSize: 10)
                textLabel.textColor = .secondaryLabelColor
                textLabel.lineBreakMode = .byTruncatingTail
                textLabel.translatesAutoresizingMaskIntoConstraints = false
                chunkView.addSubview(textLabel)

                let flagLabel = NSTextField(labelWithString: flagCount > 0 ? "\(flagCount) flags" : "")
                flagLabel.font = .systemFont(ofSize: 9)
                flagLabel.textColor = .tertiaryLabelColor
                flagLabel.translatesAutoresizingMaskIntoConstraints = false
                chunkView.addSubview(flagLabel)

                NSLayoutConstraint.activate([
                    chunkView.heightAnchor.constraint(equalToConstant: 20),
                    chunkView.widthAnchor.constraint(equalToConstant: 428),
                    dot.leadingAnchor.constraint(equalTo: chunkView.leadingAnchor),
                    dot.centerYAnchor.constraint(equalTo: chunkView.centerYAnchor),
                    dot.widthAnchor.constraint(equalToConstant: 8),
                    dot.heightAnchor.constraint(equalToConstant: 8),
                    pctLabel.leadingAnchor.constraint(equalTo: dot.trailingAnchor, constant: 6),
                    pctLabel.centerYAnchor.constraint(equalTo: chunkView.centerYAnchor),
                    pctLabel.widthAnchor.constraint(equalToConstant: 36),
                    textLabel.leadingAnchor.constraint(equalTo: pctLabel.trailingAnchor, constant: 4),
                    textLabel.centerYAnchor.constraint(equalTo: chunkView.centerYAnchor),
                    textLabel.trailingAnchor.constraint(lessThanOrEqualTo: flagLabel.leadingAnchor, constant: -4),
                    flagLabel.trailingAnchor.constraint(equalTo: chunkView.trailingAnchor),
                    flagLabel.centerYAnchor.constraint(equalTo: chunkView.centerYAnchor),
                ])

                stack.addArrangedSubview(chunkView)
            }
        }

        // ── Findings detail ───────────────────────────────────────────
        if !docResult.allFindings.isEmpty {
            addSeparator(to: stack)

            let byCategory: [(String, Finding.Category, String)] = [
                ("Watermark detected", .watermark, "🚨"),
                ("Invisible Unicode", .unicode, "⚠️"),
                ("Grammar patterns", .grammar, "📝"),
                ("LLM phrases", .phrase, "🔵"),
                ("Statistical signals", .statistical, "📊"),
                ("AI-style punctuation", .punctuation, "·"),
            ]

            for (title, cat, icon) in byCategory {
                let items = docResult.allFindings.filter { $0.category == cat }
                if items.isEmpty { continue }

                let sectionTitle = NSTextField(labelWithString: "\(icon)  \(title)")
                sectionTitle.font = .systemFont(ofSize: 12, weight: .medium)
                sectionTitle.textColor = .labelColor
                stack.addArrangedSubview(sectionTitle)

                for item in items {
                    let countStr = item.count > 1 ? "×\(item.count)  " : ""
                    let line = NSTextField(wrappingLabelWithString: "    \(countStr)\(item.name)  — \(item.reason)")
                    line.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
                    line.textColor = .secondaryLabelColor
                    line.preferredMaxLayoutWidth = 416
                    stack.addArrangedSubview(line)
                }
            }
        }

        // ── Sizing ────────────────────────────────────────────────────
        scroll.documentView = stack
        stack.layoutSubtreeIfNeeded()
        let height = min(stack.fittingSize.height + 8, 700)
        container.frame = NSRect(x: 0, y: 0, width: 460, height: height)
        scroll.frame = container.bounds
        self.view = container
        self.preferredContentSize = NSSize(width: 460, height: height)
    }

    private func addSeparator(to stack: NSStackView) {
        let sep = NSBox()
        sep.boxType = .separator
        sep.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(sep)
        sep.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -32).isActive = true
    }
}


// MARK: - Menu Bar App

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var hotKeyRef: EventHotKeyRef?
    var popover = NSPopover()
    let scanner = SlopScanner()
    var sensitivity: Sensitivity = .high

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = " slop"
            button.font = .monospacedSystemFont(ofSize: 12, weight: .medium)
        }

        rebuildMenu()
        popover.behavior = .transient
        popover.animates = true
        registerHotKey()

        let n = NSUserNotification()
        n.title = "Slop Detector"
        n.informativeText = "Running (\(sensitivity.menuLabel)). Press ⌘⇧D with text selected."
        NSUserNotificationCenter.default.deliver(n)
    }

    func rebuildMenu() {
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Scan Selected Text  ⌘⇧D", action: #selector(scanSelected), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Scan Clipboard", action: #selector(scanFromClipboard), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())

        let sensitivityMenu = NSMenu()
        for level in Sensitivity.allCases {
            let item = NSMenuItem(title: level.label, action: #selector(setSensitivity(_:)), keyEquivalent: "")
            item.target = self
            item.tag = level.rawValue
            item.state = level == sensitivity ? .on : .off
            sensitivityMenu.addItem(item)
        }
        let sensitivityItem = NSMenuItem(title: "Sensitivity: \(sensitivity.menuLabel)", action: nil, keyEquivalent: "")
        sensitivityItem.submenu = sensitivityMenu
        menu.addItem(sensitivityItem)

        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
        statusItem.menu = menu
    }

    @objc func setSensitivity(_ sender: NSMenuItem) {
        guard let level = Sensitivity(rawValue: sender.tag) else { return }
        sensitivity = level
        rebuildMenu()
        if let button = statusItem.button {
            button.title = " slop·\(sensitivity.menuLabel.prefix(1).lowercased())"
        }
    }

    func registerHotKey() {
        var hotKeyID = EventHotKeyID()
        hotKeyID.signature = OSType(0x534C4F50)
        hotKeyID.id = 1
        let modifiers: UInt32 = UInt32(cmdKey | shiftKey)
        let keyCode: UInt32 = 2
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

    @objc func scanSelected() {
        let pasteboard = NSPasteboard.general
        let savedChangeCount = pasteboard.changeCount

        let source = CGEventSource(stateID: .combinedSessionState)
        let cDown = CGEvent(keyboardEventSource: source, virtualKey: 0x08, keyDown: true)
        let cUp = CGEvent(keyboardEventSource: source, virtualKey: 0x08, keyDown: false)
        cDown?.flags = CGEventFlags.maskCommand
        cUp?.flags = CGEventFlags.maskCommand
        cDown?.post(tap: .cgSessionEventTap)
        cUp?.post(tap: .cgSessionEventTap)

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            guard let self = self else { return }
            if pasteboard.changeCount != savedChangeCount,
               let text = pasteboard.string(forType: .string), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                self.runScan(text)
            } else if let text = pasteboard.string(forType: .string), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
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
        let result = scanner.scanDocument(text, sensitivity: sensitivity)

        // Console
        print("\n══════════════════════════════════════════════")
        print("  \(Int(result.overallScore))% AI · \(result.verdict) · \(result.totalWordCount) words")
        print("══════════════════════════════════════════════")
        if result.chunks.count > 1 {
            for (i, chunk) in result.chunks.enumerated() {
                let bar = String(repeating: "█", count: Int(chunk.score / 5))
                let pad = String(repeating: "░", count: 20 - Int(chunk.score / 5))
                let preview = String(chunk.text.prefix(50)).replacingOccurrences(of: "\n", with: " ")
                print("  ¶\(i+1) \(bar)\(pad) \(Int(chunk.score))%  \"\(preview)…\"")
            }
            print("  ──────────────────────────────────────────────")
        }
        for f in result.allFindings {
            let icon = f.category == .watermark ? "🚨" : f.category == .unicode ? "⚠️" : f.category == .grammar ? "📝" : f.category == .statistical ? "📊" : "🔵"
            let c = f.count > 1 ? " (×\(f.count))" : ""
            print("  \(icon)  \(f.name)\(c) — \(f.reason)")
        }
        print("══════════════════════════════════════════════\n")

        // Popover
        popover.contentViewController = ResultViewController(docResult: result, text: text)
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

class NotificationDelegate: NSObject, NSUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: NSUserNotificationCenter, shouldPresent notification: NSUserNotification) -> Bool { true }
}
let notifDelegate = NotificationDelegate()
NSUserNotificationCenter.default.delegate = notifDelegate

app.run()
