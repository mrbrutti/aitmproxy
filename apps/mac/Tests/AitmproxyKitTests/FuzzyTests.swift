import Testing
@testable import AitmproxyKit

@Suite struct FuzzyTests {
    @Test func subsequenceMatchesAndRejects() {
        #expect(Fuzzy.match("fr", in: "flow.replay") != nil)
        #expect(Fuzzy.match("xyz", in: "flow.replay") == nil)
        #expect(Fuzzy.match("", in: "anything")?.score == 1)
    }

    @Test func wordStartsAndRunsRankHigher() {
        let replay = Fuzzy.match("fr", in: "flow.replay")?.score ?? 0
        let refresh = Fuzzy.match("fr", in: "browser.refresh")?.score ?? 0
        #expect(replay > refresh)
        let run = Fuzzy.match("rep", in: "flow.replay")?.score ?? 0
        let scattered = Fuzzy.match("rep", in: "rate.limit.export")?.score ?? 0
        #expect(run > scattered)
    }

    @Test func nameOutranksDescription() {
        let byName = Fuzzy.score("kill", name: "flow.kill", description: "Abort a flow")
        let byDescription = Fuzzy.score("kill", name: "flow.resume", description: "Resume instead of kill")
        #expect(byName > byDescription)
        #expect(byDescription > 0)
    }

    @Test func positionsPointAtMatchedCharacters() {
        let m = Fuzzy.match("fl", in: "flow.list")
        #expect(m?.positions == [0, 1])
    }
}
