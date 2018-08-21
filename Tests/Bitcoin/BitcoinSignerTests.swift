// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
import XCTest

class BitcoinSignerTests: XCTestCase {
    func testSign() {
        let inputs = [
            BitcoinTransactionInput(
                previousOutput: BitcoinOutPoint(hash: Data(hexString: "4d49a71ec9da436f71ec4ee231d04f292a29cd316f598bb7068feccabdc59485")!, index: 0 as UInt32),
                script: BitcoinScript(bytes: []),
                sequence: 4294967295),
            ]
        let outputs = [BitcoinTransactionOutput]()
        let tx = BitcoinTransaction(version: 1, inputs: inputs, outputs: outputs, lockTime: 0)

        var encoded = Data()
        tx.encode(into: &encoded)
        SignatureHashType.all.rawValue.encode(into: &encoded)
        XCTAssertEqual(encoded.hexString, "01000000018594c5bdcaec8f06b78b596f31cd292a294fd031e24eec716f43dac91ea7494d000000001976a91491b24bf9f5288532960ac687abb035127b1d28a588acffffffff000000000001000000")

        BitcoinSigner.sign(transaction: tx, provider: TestProvider())

        XCTAssertEqual(tx.inputs[0].script.data.hexString, "48304502210096a75056c9e2cc62b7214777b3d2a592cfda7092520126d4ebfcd6d590c99bd8022051bb746359cf98c0603f3004477eac68701132380db8facba19c89dc5ab5c5e201410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    }
}

class TestProvider: SigningProvider {
    let pk: PrivateKey = {
        let data = Crypto.base58Decode("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", expectedSize: Bitcoin.privateKeySize + 1)!
        return PrivateKey(data: data.dropFirst())!
    }()

    func getCoin(outPoint: BitcoinOutPoint) -> BitcoinCoin {
        let out = BitcoinTransactionOutput(value: 0, script: BitcoinScript(data: Data(hexString: "76a91491b24bf9f5288532960ac687abb035127b1d28a588ac")!))
        return BitcoinCoin(out: out, height: 1, coinBase: true)
    }

    func getScript(scriptid: Data) -> BitcoinScript? {
        return nil
    }

    func getPubKey(address: Data) -> BitcoinPublicKey? {
        return pk.publicKey(for: .bitcoin) as? BitcoinPublicKey
    }

    func getKey(address: Data) -> PrivateKey? {
        return pk
    }
}
