#!/usr/bin/env swift
// Generates Sources/AitmproxyKit/LanguageDefs.swift from the shared language
// definitions under docs/design/languages/, the single source of truth the web
// and terminal UIs also consume. The three files — the Rhai token grammar, the
// Rhai API catalog, and the PoC-YAML key schema — are embedded verbatim as
// escaped Swift string constants; LanguageCatalog.swift decodes them at load.
//   swift tools/gen-langs.swift            (from apps/mac)
//   swift tools/gen-langs.swift <languages-dir> <LanguageDefs.swift>
// Rhai highlighting, PoC-YAML highlighting, and both autocomplete catalogs all
// derive from these constants, so no surface hard-codes a keyword, host
// function, or PoC key (UI spec §Part-1, "A surface never hard-codes…").
import Foundation

let here = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let packageRoot = here.deletingLastPathComponent()
let langDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1]
    : packageRoot.appending(path: "../../docs/design/languages").standardized.path
let outputPath = CommandLine.arguments.count > 2 ? CommandLine.arguments[2]
    : packageRoot.appending(path: "Sources/AitmproxyKit/LanguageDefs.swift").path

/// One embedded constant: the JSON file's text as a Swift double-quoted literal.
func read(_ name: String) -> String {
    let path = URL(fileURLWithPath: langDir).appending(path: name).path
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
        FileHandle.standardError.write("cannot read \(path)\n".data(using: .utf8)!)
        exit(1)
    }
    // Validate it parses, so a broken definition fails generation, not at runtime.
    guard let data = text.data(using: .utf8), (try? JSONSerialization.jsonObject(with: data)) != nil else {
        FileHandle.standardError.write("\(name) is not valid JSON\n".data(using: .utf8)!)
        exit(1)
    }
    return text
}

/// Escapes a JSON blob into a single Swift double-quoted string literal. Always
/// safe (unlike raw strings, whose `"#` delimiters collide with Rhai's raw-string
/// markers in the grammar file).
func literal(_ text: String) -> String {
    var out = "\""
    for scalar in text.unicodeScalars {
        switch scalar {
        case "\\": out += "\\\\"
        case "\"": out += "\\\""
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default: out.unicodeScalars.append(scalar)
        }
    }
    out += "\""
    return out
}

let rhaiGrammar = read("rhai.grammar.json")
let rhaiAPI = read("rhai.api.json")
let pocSchema = read("poc-yaml.schema.json")

var out = ""
out += "// Generated from docs/design/languages/*.json by tools/gen-langs.swift. Do not edit.\n"
out += "// The shared Rhai grammar, Rhai API catalog, and PoC-YAML schema, embedded verbatim.\n"
out += "// LanguageCatalog.swift decodes these; re-run the generator when the definitions change.\n"
out += "\n"
out += "enum LanguageDefs {\n"
out += "    static let rhaiGrammarJSON = \(literal(rhaiGrammar))\n\n"
out += "    static let rhaiAPIJSON = \(literal(rhaiAPI))\n\n"
out += "    static let pocYAMLSchemaJSON = \(literal(pocSchema))\n"
out += "}\n"

do {
    try out.write(toFile: outputPath, atomically: false, encoding: .utf8)
    print("wrote \(outputPath)")
} catch {
    FileHandle.standardError.write("cannot write \(outputPath): \(error)\n".data(using: .utf8)!)
    exit(1)
}
