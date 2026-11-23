var gDeinitCount: Int32 = 0

@_silgen_name("objc_getClass")
func c_objc_getClass(_ name: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?

@_silgen_name("sel_registerName")
func c_sel_registerName(_ name: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?

@_silgen_name("objc_msgSend")
func c_objc_msgSend(_ obj: UnsafeMutableRawPointer, _ sel: UnsafeMutableRawPointer, _ arg: UnsafePointer<CChar>?) -> UnsafeMutableRawPointer?

@_silgen_name("NSLog")
func c_NSLog(_ fmt: UnsafeMutableRawPointer, _ arg: UnsafeMutableRawPointer)

class Node {
    var value: Int
    var next: Node?
    init(_ v: Int, next: Node? = nil) {
        self.value = v
        self.next = next
    }
    deinit {
        gDeinitCount += 1
    }
}

func makeList() -> Int {
    let a = Node(10)
    let b = Node(20, next: a)
    let c = Node(12, next: b)
    var sum = 0
    var cur: Node? = c
    while let n = cur {
        sum += n.value
        cur = n.next
    }
    return sum
}

@_cdecl("main")
public func main_entry(argc: Int32, argv: UnsafePointer<UnsafePointer<CChar>?>?) -> Int32 {
    let total = makeList()
    if total != 42 { return 10 }
    if gDeinitCount != 3 { return 11 }

    // Swift -> Foundation (NSString + NSLog)
    if let nsStringCls = c_objc_getClass("NSString") {
        let selStr = c_sel_registerName("stringWithUTF8String:")!
        let selLen = c_sel_registerName("length")!
        if let s = "Swift->Foundation OK".withCString({ c_objc_msgSend(nsStringCls, selStr, $0) }) {
            let len = Int(bitPattern: c_objc_msgSend(s, selLen, nil))
            if len != 20 { return 12 }
            if let fmt = "%@".withCString({ c_objc_msgSend(nsStringCls, selStr, $0) }) {
                c_NSLog(fmt, s)
            }
        } else {
            return 13
        }
    } else {
        return 14
    }

    print("swift_runtime_ok total=42 deinit=3")
    return 0
}
