// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
import XCTest

class BitcoinAddressTests: XCTestCase {
    func testInvalid() {
        XCTAssertNil(BitcoinAddress(string: "abc"))
        XCTAssertNil(BitcoinAddress(string: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
        XCTAssertNil(BitcoinAddress(string: "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"))
    }

    func testInitWithString() {
        let address = BitcoinAddress(string: "1AC4gh14wwZPULVPCdxUkgqbtPvC92PQPN")

        XCTAssertNotNil(address)
        XCTAssertEqual(address!.description, "1AC4gh14wwZPULVPCdxUkgqbtPvC92PQPN")
    }

    func testFromPrivateKey() {
        let data = Crypto.base58Decode("5K6EwEiKWKNnWGYwbNtrXjA8KKNntvxNKvepNqNeeLpfW7FSG1v", expectedSize: Bitcoin.privateKeySize + 1)!
        let privateKey = PrivateKey(data: data.dropFirst())!
        let address = privateKey.publicKey(for: .bitcoin, compressed: true).address

        XCTAssertEqual(address.description, "3EpNJiTASbZ6DeNA7QZ7bPEz82Y42W8Rd7")
    }

    func testIsValid() {
        XCTAssertFalse(BitcoinAddress.isValid(string: "abc"))
        XCTAssertFalse(BitcoinAddress.isValid(string: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
        XCTAssertFalse(BitcoinAddress.isValid(string: "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"))
        XCTAssertTrue(BitcoinAddress.isValid(string: "1AC4gh14wwZPULVPCdxUkgqbtPvC92PQPN"))
    }
}
