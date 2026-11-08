import Foundation

/// Generates passwords and passphrases with the system CSPRNG, without modulo bias.
public enum PasswordGenerator {
    public struct Options: Equatable, Sendable, Codable {
        public var length = 20
        public var lowercase = true
        public var uppercase = true
        public var digits = true
        public var symbols = true

        public init() {}
    }

    public struct PassphraseOptions: Equatable, Sendable, Codable {
        public var words = 5
        public var separator = "-"
        public var capitalize = false
        /// Appends a digit to one random word, for sites that insist on one.
        public var includeDigit = false

        public init() {}
    }

    static let lower = Array("abcdefghijklmnopqrstuvwxyz")
    static let upper = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    static let numbers = Array("0123456789")
    static let specials = Array("!#$%&()*+,-./:;<=>?@[]^_{|}~")

    public static func password(_ options: Options = Options()) -> String {
        var rng = SystemRandomNumberGenerator()
        return password(options, using: &rng)
    }

    /// Picks from the selected character classes, guaranteeing at least one of each.
    public static func password(_ options: Options, using rng: inout some RandomNumberGenerator) -> String {
        let classes = [
            options.lowercase ? lower : nil, options.uppercase ? upper : nil, options.digits ? numbers : nil,
            options.symbols ? specials : nil,
        ].compactMap { $0 }
        guard !classes.isEmpty else { return "" }
        let length = max(options.length, classes.count)
        let all = classes.flatMap { $0 }
        var chars = classes.map { $0.randomElement(using: &rng)! }
        while chars.count < length { chars.append(all.randomElement(using: &rng)!) }
        chars.shuffle(using: &rng)
        return String(chars)
    }

    public static func passphrase(_ options: PassphraseOptions = PassphraseOptions()) -> String {
        var rng = SystemRandomNumberGenerator()
        return passphrase(options, using: &rng)
    }

    public static func passphrase(_ options: PassphraseOptions, using rng: inout some RandomNumberGenerator) -> String {
        var words = (0..<max(options.words, 1)).map { _ in wordlist.randomElement(using: &rng)! }
        if options.capitalize { words = words.map { $0.prefix(1).uppercased() + $0.dropFirst() } }
        if options.includeDigit {
            let i = Int.random(in: 0..<words.count, using: &rng)
            words[i] += String(Int.random(in: 0...9, using: &rng))
        }
        return words.joined(separator: options.separator)
    }

    /// Entropy in bits, for the strength label.
    public static func entropy(_ options: Options) -> Double {
        let size = (options.lowercase ? 26 : 0) + (options.uppercase ? 26 : 0) + (options.digits ? 10 : 0) + (options.symbols ? specials.count : 0)
        return size == 0 ? 0 : Double(options.length) * log2(Double(size))
    }

    public static func entropy(_ options: PassphraseOptions) -> Double {
        Double(options.words) * log2(Double(wordlist.count)) + (options.includeDigit ? log2(10) + log2(Double(options.words)) : 0)
    }

    /// The EFF large wordlist (7,776 words), from https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt.
    public static let wordlist: [String] = {
        guard let url = Bundle.module.url(forResource: "eff_large_wordlist", withExtension: "txt"),
            let text = try? String(contentsOf: url, encoding: .utf8)
        else { return [] }
        return text.split(separator: "\n").map(String.init)
    }()
}
