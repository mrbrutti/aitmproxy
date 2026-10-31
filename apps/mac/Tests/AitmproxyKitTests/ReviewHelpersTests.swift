import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ReviewHelpersTests {
    @Test func clockTimeDropsMilliseconds() {
        // A half second is exact in binary; .120 would decode as .119999 and read 119 ms.
        let date = Date(timeIntervalSince1970: 1_700_000_000.5) // 2023-11-14 22:13:20.500 UTC
        let utc = TimeZone(identifier: "UTC")!
        #expect(Format.time(date, zone: utc) == "22:13:20.500")
        #expect(Format.clockTime(date, zone: utc) == "22:13:20")
    }

    @Test func firstClauseCutsAtTheFirstBreak() {
        #expect("timeout. retrying".firstClause == "timeout")
        #expect("a — b".firstClause == "a")
        #expect("x\ny".firstClause == "x")
        #expect("scope.add is operator-only; add the host in Settings".firstClause == "scope.add is operator-only")
        #expect("plain".firstClause == "plain")
    }

    @Test func roleWarningOnlySilentForTheActiveEmbeddedCore() {
        #expect(roleWarningApplies(activeKind: .embedded, embeddedConnectionPresent: true) == false)
        // An external connection warns even while the dormant embedded controller still reports itself.
        #expect(roleWarningApplies(activeKind: .external, embeddedConnectionPresent: true) == true)
        #expect(roleWarningApplies(activeKind: .embedded, embeddedConnectionPresent: false) == true)
    }
}
