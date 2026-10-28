import Foundation

/// The decoded shared language definitions (`docs/design/languages/*.json`,
/// embedded by `tools/gen-langs.swift` into `LanguageDefs`). One source of
/// truth for Rhai + PoC-YAML highlighting and autocomplete, shared with the web
/// and TUI surfaces so the three never drift (UI-ext spec §Part-1).
public enum LanguageCatalog {
    public static let rhai: RhaiCatalog = RhaiCatalog.decoded()
    public static let poc: PocCatalog = PocCatalog.decoded()
}

// MARK: - Rhai

/// Rhai keywords/literals (for the tokenizer) and the API catalog (for
/// completion), from `rhai.grammar.json` + `rhai.api.json`.
public struct RhaiCatalog: Sendable {
    /// Control keywords (`fn`, `let`, `if`, …) → the `keyword` token.
    public let keywords: Set<String>
    /// `true` / `false` → the `boolean` token.
    public let literals: Set<String>
    /// The ten hook names in declaration order (top-level completion pool).
    public let hookNames: [String]
    /// Globals usable inside a hook body: the top-level host objects + the DSL
    /// helpers (`log`, `http`, …, `b64_encode`, …), in declaration order.
    public let bodyGlobals: [String]
    /// Member chains: a receiver path (`flow.request`) → its member last
    /// segments in declaration order (`method`, `url`, …).
    public let members: [String: [String]]

    private struct Grammar: Decodable {
        var keywords: [String]
        var literals: [String]
    }

    private struct API: Decodable {
        struct Entry: Decodable { var name: String }
        var hooks: [Entry]
        var flow: [Entry]
        var msg: [Entry]
        var globals: [Entry]
        var dsl: [Entry]
    }

    static func decoded() -> RhaiCatalog {
        let grammar = try! JSONDecoder().decode(Grammar.self, from: Data(LanguageDefs.rhaiGrammarJSON.utf8))
        let api = try! JSONDecoder().decode(API.self, from: Data(LanguageDefs.rhaiAPIJSON.utf8))

        var members: [String: [String]] = [:]
        func record(_ name: String) {
            guard let dot = name.lastIndex(of: ".") else { return }
            let parent = String(name[..<dot])
            let child = String(name[name.index(after: dot)...])
            if members[parent]?.contains(child) != true { members[parent, default: []].append(child) }
        }
        for entry in api.flow + api.msg + api.globals { record(entry.name) }

        let topLevelGlobals = api.globals.map(\.name).filter { !$0.contains(".") }
        return RhaiCatalog(
            keywords: Set(grammar.keywords),
            literals: Set(grammar.literals),
            hookNames: api.hooks.map(\.name),
            bodyGlobals: topLevelGlobals + api.dsl.map(\.name),
            members: members)
    }
}

// MARK: - PoC YAML

/// The PoC-YAML key schema (`poc-yaml.schema.json`) for schema-aware
/// completion: a node tree walked by YAML nesting (keys at a level, enum values
/// after a key), with `$ref` into `$defs`.
public struct PocCatalog: Sendable {
    public let root: PocNode
    let defs: [String: PocNode]

    /// Follows a `$ref` to its definition; returns the node unchanged otherwise.
    public func resolve(_ node: PocNode) -> PocNode {
        guard let ref = node.ref, let name = ref.split(separator: "/").last,
              let target = defs[String(name)] else { return node }
        return target
    }

    private struct Doc: Decodable {
        var type: String?
        var keys: [String: PocNode]?
        var defs: [String: PocNode]?
        enum CodingKeys: String, CodingKey { case type, keys, defs = "$defs" }
    }

    static func decoded() -> PocCatalog {
        let doc = try! JSONDecoder().decode(Doc.self, from: Data(LanguageDefs.pocYAMLSchemaJSON.utf8))
        let root = PocNode(type: doc.type, keys: doc.keys)
        return PocCatalog(root: root, defs: doc.defs ?? [:])
    }
}

/// One node of the PoC-YAML schema: a map (with child `keys`), a list (with an
/// element `items`), an `enum`, or a `$ref`.
public final class PocNode: Decodable, @unchecked Sendable {
    public let type: String?
    public let keys: [String: PocNode]?
    public let items: PocNode?
    public let enumValues: [String]?
    public let ref: String?

    enum CodingKeys: String, CodingKey {
        case type, keys, items, enumValues = "enum", ref = "$ref"
    }

    init(type: String?, keys: [String: PocNode]?) {
        self.type = type
        self.keys = keys
        self.items = nil
        self.enumValues = nil
        self.ref = nil
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decodeIfPresent(String.self, forKey: .type)
        keys = try c.decodeIfPresent([String: PocNode].self, forKey: .keys)
        items = try c.decodeIfPresent(PocNode.self, forKey: .items)
        enumValues = try c.decodeIfPresent([String].self, forKey: .enumValues)
        ref = try c.decodeIfPresent(String.self, forKey: .ref)
    }
}
