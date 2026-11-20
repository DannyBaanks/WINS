protocol Summarizable {
    func summary() -> String
}

enum ParseError: Error {
    case negativeInput
}

struct Pair<A, B> {
    var first: A
    var second: B
}

struct Report: Summarizable {
    var title: String
    var total: Int
    func summary() -> String {
        return "\(title): \(total)"
    }
}

func validate(_ x: Int) throws -> Int {
    if x < 0 { throw ParseError.negativeInput }
    return x * 3
}

@_cdecl("main")
public func main_entry(argc: Int32, argv: UnsafePointer<UnsafePointer<CChar>?>?) -> Int32 {
    // 1. Array + map/filter/reduce
    var nums = [1, 2, 3, 4]
    nums.append(5)
    let evenDoubled = nums.filter { $0 % 2 == 0 }.map { $0 * 10 }
    let sum = evenDoubled.reduce(0, +)
    if sum != 60 { return 10 }

    // 2. Dictionary (uses Hasher + arc4random_buf)
    var scores: [String: Int] = ["alice": 10, "bob": 20]
    scores["carol"] = 30
    let totalScore = (scores["alice"] ?? 0) + (scores["bob"] ?? 0) + (scores["carol"] ?? 0)
    if totalScore != 60 { return 11 }

    // 3. String interpolation, concatenation, count, equality
    var label = "wins"
    label += "-swift"
    if label != "wins-swift" || label.count != 10 { return 12 }

    // 4. Generics + Protocol
    let pair = Pair(first: label, second: totalScore)
    let report = Report(title: pair.first, total: pair.second)
    if report.summary() != "wins-swift: 60" { return 13 }

    // 5. Error handling (throws / do / try / catch) + Result
    var caught = false
    do {
        _ = try validate(-5)
        return 14
    } catch {
        caught = true
    }
    if !caught { return 15 }

    let okVal = (try? validate(7)) ?? 0
    if okVal != 21 { return 16 }

    print("swift_stdlib_ok \(report.summary()) okVal=\(okVal)")
    return 0
}
