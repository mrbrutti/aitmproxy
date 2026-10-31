import SwiftUI

/// One ordered categorical colour scale for charts, so the same position means the
/// same colour on every chart (the Scan injection-type bars and the Timing phases
/// used to run different orderings of `Tok.Mark`). `Tok.Mark` stays the user's flag
/// palette; charts read this shared scale instead of each picking its own order.
enum ChartPalette {
    static let categorical: [Color] = [
        Tok.Mark.blue.color, Tok.Mark.green.color, Tok.Mark.orange.color,
        Tok.Mark.purple.color, Tok.Mark.teal.color, Tok.Mark.pink.color,
        Tok.Mark.indigo.color, Tok.Mark.mint.color,
    ]
}
