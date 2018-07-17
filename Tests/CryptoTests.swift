// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import TrustCore
import XCTest

class CryptoTests: XCTestCase {
    func testSign() {
        let hash = Data(hexString: "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F")!
        let privateKey = Data(hexString: "D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759")!
        let signature = Crypto.sign(hash: hash, privateKey: privateKey)
        let publicKey = Crypto.getPublicKey(from: privateKey)

        XCTAssertEqual(signature.count, 65)
        XCTAssertEqual(signature.hexString, "e56cfc6bddb0f803ee41c163816c3aa924ea0aae937294daf6a55f948aab8b463746cd528a3ad0102b431d7c7cecec7d92b910fe57c1213514c12206c41f1fef00")
        XCTAssertTrue(Crypto.verify(signature: signature, message: hash, publicKey: publicKey))
    }

    func testSignDER() {
        let hash = Data(hexString: "52204d20fd0131ae1afd173fd80a3a746d2dcc0cddced8c9dc3d61cc7ab6e966")!
        let privateKey = Data(hexString: "16f243e962c59e71e54189e67e66cf2440a1334514c09c00ddcc21632bac9808")!
        let signature = Crypto.signAsDER(hash: hash, privateKey: privateKey)

        XCTAssertEqual(signature.hexString, "3044022055f4b20035cbb2e85b7a04a0874c80d5822758f4e47a9a69db04b29f8b218f920220491e6a13296cfe2186da3a3ca565a179def3808b12d184553a8e3acfe1467273")
    }

    func testGetPublicKey() {
        let privateKey = Data(hexString: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")!
        XCTAssertEqual(Crypto.getPublicKey(from: privateKey).hexString, "0432d87c5cd4b31d81c5b010af42a2e413af253dc3a91bd3d53c6b2c45291c3de71633bf7793447a0d3ddde601f8d21668fca5b33324f14ebe7516eab0da8bab8f")
    }

    func testGetCompressedPublicKey() {
        let privateKey = Data(hexString: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")!
        XCTAssertEqual(Crypto.getCompressedPublicKey(from: privateKey).hexString, "0332d87c5cd4b31d81c5b010af42a2e413af253dc3a91bd3d53c6b2c45291c3de7")
    }

    func testDeriveSeed() {
        let mnemonic = "often tobacco bread scare imitate song kind common bar forest yard wisdom"
        let passphrase = "testtest123"
        let seed = Data(hexString: "b4186ab8ac0ebfd3c20f992d0b602639fe59f0e4d2e66dea487194580e0aa0031387c9f30488a7628ed7350a63dd97e1acb259896082e3b34a1ff0dd85c287d1")!

        XCTAssertEqual(Crypto.deriveSeed(mnemonic: mnemonic, passphrase: passphrase), seed)
    }

    func testEncode() {
        let message = "c61d43dc5bb7a4e754d111dae8105b6f25356492df5e50ecb33b858d94f8c338"
        let expected = "ship tube warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        let words = Crypto.generateMnemonic(seed: Data(hexString: message)!)
        XCTAssertEqual(words, expected)
    }

    func testValid() {
        let mnemonic = "ship tube warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        XCTAssertTrue(Crypto.isValid(mnemonic: mnemonic))
    }

    func testInvalid() {
        let mnemonic = "ship turd warfare resist kid inhale fashion captain sustain dog bitter tattoo fashion rather enter type extend grain solve arch sun ladder artefact bronze"
        XCTAssertFalse(Crypto.isValid(mnemonic: mnemonic))
    }
}
