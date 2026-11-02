// The Jobs view's motion vocabulary (Jobs view spec D12).
//
// Lives in the app target beside Tokens.swift because `Tok.*` is app-only and
// the Kit has no SwiftUI. Every constant is a `Tok.Motion` token; this file
// carries no numeric literal of its own, so a duration changes in exactly one
// place: docs/design/tokens.json.
import SwiftUI

enum ScanMotion {
    /// Digit ticks on every live number (KPI numerals, lane labels, row cells,
    /// elapsed): `motion.counter`, 150 ms.
    static let counter = Tok.Motion.counter
    /// The lane fill, the now mark and the ring easing to a new value; a
    /// falling value eases down, never clamps: `motion.progress`, 250 ms.
    static let progress = Tok.Motion.progress
    /// The chip's crossfade and the card edge's recolour: `motion.popover`,
    /// 160 ms.
    static let state = Tok.Motion.popover
    /// The card's blocks rising and fading in, the one named entrance:
    /// `motion.sheet`, 220 ms.
    static let entrance = Tok.Motion.sheet
    /// The delay between the card's blocks in that entrance: `motion.stagger`,
    /// 60 ms.
    static let stagger = Tok.Motion.stagger
    /// The now tag giving way to the end sentence and the verb swap:
    /// `motion.sheet`, 220 ms.
    static let endSwap = Tok.Motion.sheet
    /// The row's Cancel appearing on hover: `motion.hover`, 100 ms.
    static let hoverReveal = Tok.Motion.hover
    /// One breath of the two breathing dots (the now mark's and the
    /// cancelling dot): `motion.interceptPulse`, 1200 ms.
    static let breath = Tok.Motion.interceptPulse

    /// The ease-out curve every Jobs travel and fade uses, for `duration` seconds.
    static func ease(_ duration: Double) -> Animation { Tok.Motion.easeOut(duration) }

    /// The breathing animation: the pulse curve over one breath, repeating
    /// forever and reversing, so a dot's opacity rises and falls.
    static func breathe() -> Animation { Tok.Motion.pulse(breath).repeatForever(autoreverses: true) }
}
