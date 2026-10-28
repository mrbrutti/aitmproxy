import AitmBusClient
import AitmproxyKit
import AppKit

/// Filters (S-031–S-034): the stacked bar, the Advanced text and saved filters.
extension Session {
    /// The text form of whatever is filtering right now.
    var currentFilterExpressionText: String { filterAdvanced ? filterText : filterStack.text }

    /// The rows view of the Advanced text, when the expression is flat.
    var filterStackFromText: FilterStack? {
        guard filterAdvanced, filterError == nil else { return nil }
        return filterExpression.stack
    }

    func setFilterAdvanced(_ advanced: Bool) {
        if advanced {
            filterText = filterStack.text
            filterAdvanced = true
            parseFilterText()
        } else {
            if let stack = filterExpression.stack { filterStack = stack }
            filterAdvanced = false
            recompileFilter(from: filterStack.expression)
        }
    }

    func parseFilterText() {
        do {
            let expression = try FilterExpression.parse(filterText)
            filterError = nil
            recompileFilter(from: expression)
        } catch {
            filterError = error
            compiledFilter = nil
            filterExpression = .matchAll
        }
    }

    func recompileFilter(from expression: FilterExpression) {
        filterExpression = expression
        compiledFilter = expression == .matchAll ? nil : CompiledFilter(expression)
    }

    func clearFilter() {
        filterStack = FilterStack(rows: [FilterRow(.url, .contains)])
        filterText = ""
        filterError = nil
        compiledFilter = nil
        filterExpression = .matchAll
    }

    func loadSavedFilters() {
        savedFilters = (try? savedFilterStore.load()) ?? []
    }

    func saveFilter(named name: String) {
        let expression = currentFilterExpressionText
        guard !name.isEmpty, !expression.isEmpty else { return }
        savedFilters.removeAll { $0.name == name }
        savedFilters.append(SavedFilter(name: name, expression: expression))
        try? savedFilterStore.save(savedFilters)
    }

    func deleteSavedFilter(_ saved: SavedFilter) {
        savedFilters.removeAll { $0.id == saved.id }
        try? savedFilterStore.save(savedFilters)
    }

    /// Sets both the rows and the Advanced text (S-033).
    func applySavedFilter(_ saved: SavedFilter) {
        guard let expression = try? FilterExpression.parse(saved.expression) else { return }
        if let stack = expression.stack {
            filterAdvanced = false
            filterStack = stack
        } else {
            filterAdvanced = true
            filterText = saved.expression
        }
        filterBarVisible = true
    }
}
