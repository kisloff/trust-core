// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import BigInt
import Foundation
import TrezorCrypto

/// Provides keys and other information to a `BitcoinSigner`.
public protocol SigningProvider {
    /// Returns the `BitcoinCoin` for a specific out point.
    func getCoin(outPoint: BitcoinOutPoint) -> BitcoinCoin

    /// Returns a script by its address.
    func getScript(scriptid: Data) -> BitcoinScript?

    /// Returns a public key by its address.
    func getPubKey(address: Data) -> BitcoinPublicKey?

    /// Returns a private key by its address.
    func getKey(address: Data) -> PrivateKey?
}

/// Bitcoin transaction signer
public final class BitcoinSigner {
    var creator: BaseSignatureCreator
    var provider: SigningProvider
    var sigdata = SignatureData()

    init(creator: BaseSignatureCreator, provider: SigningProvider) {
        self.creator = creator
        self.provider = provider
    }

    /// Signs a Bitcoin transaction.
    public static func sign(transaction: BitcoinTransaction, provider: SigningProvider) {
        let hashType = SignatureHashType.all
        let signer = BitcoinSigner(creator: TransactionSignatureCreator(transaction: transaction, index: 0, amount: 0, hashType: hashType), provider: provider)

        // Sign what we can:
        for (input, index) in zip(transaction.inputs, transaction.inputs.indices) {
            let coin = provider.getCoin(outPoint: input.previousOutput)
            if coin.isSpent {
                continue
            }
            let prevPubKey = coin.out.script
            let amount = coin.out.value

            var sigdata = SignatureData(transaction: transaction, index: index)
            signer.creator = TransactionSignatureCreator(transaction: transaction, index: index, amount: amount, hashType: .all)
            // Only sign SIGHASH_SINGLE if there's a corresponding output:
            if !hashType.single || index < transaction.outputs.count {
                signer.produceSignature(fromPubKey: prevPubKey, sigdata: &sigdata)
            }

            input.script = sigdata.scriptSig
            input.scriptWitness = sigdata.scriptWitness
        }
    }

    @discardableResult
    func produceSignature(fromPubKey: BitcoinScript, sigdata: inout SignatureData) -> Bool {
        if sigdata.complete {
            return true
        }

        var result = [Data]()
        var whichType = TransactionType.nonstandard
        var solved = SignStep(scriptPubKey: fromPubKey, ret: &result, whichTypeRet: &whichType, sigversion: SigVersion.base, sigdata: &sigdata)
        var P2SH = false
        var subScript = [UInt8]()
        sigdata.scriptWitness.stack.removeAll()

        if solved && whichType == .scriptHash {
            // Solver returns the subscript that needs to be evaluated
            // the final scriptSig is the signatures from that
            // and then the serialized subscript:
            subScript = Array(result[0])
            sigdata.redeem_script = BitcoinScript(bytes: subScript)
            solved = solved && SignStep(scriptPubKey: BitcoinScript(bytes: subScript), ret: &result, whichTypeRet: &whichType, sigversion: SigVersion.base, sigdata: &sigdata) && whichType != .scriptHash
            P2SH = true
        }

        if solved && whichType == .witnessV0Keyhash {
            let witnessscript = BitcoinScript(bytes: [])
            witnessscript.bytes = [OpCode.OP_DUP, OpCode.OP_HASH160]
            witnessscript.bytes.append(contentsOf: result[0])
            witnessscript.bytes.append(contentsOf: [OpCode.OP_EQUALVERIFY, OpCode.OP_CHECKSIG])

            var subType = TransactionType.nonstandard
            solved = solved && SignStep(scriptPubKey: witnessscript, ret: &result, whichTypeRet: &subType, sigversion: SigVersion.witnessV0, sigdata: &sigdata)
            sigdata.scriptWitness.stack = result
            sigdata.witness = true
            result.removeAll()
        } else if solved && whichType == .witnessV0ScriptHash {
            let witnessscript = BitcoinScript(data: result[0])
            sigdata.witness_script = witnessscript
            var subType = TransactionType.nonstandard
            solved = solved && SignStep(scriptPubKey: witnessscript, ret: &result, whichTypeRet: &subType, sigversion: SigVersion.witnessV0, sigdata: &sigdata) && subType != .scriptHash && subType != .witnessV0ScriptHash && subType != .witnessV0Keyhash
            result.append(Data(bytes: witnessscript.data))
            sigdata.scriptWitness.stack = result
            sigdata.witness = true
            result.removeAll()
        } else if solved && whichType == .witnessUnknown {
            sigdata.witness = true
        }

        if P2SH {
            result.append(Data(bytes: subScript))
        }
        sigdata.scriptSig = PushAll(values: result)

        // Test solution
        sigdata.complete = solved // && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker())
        return sigdata.complete
    }

    private func SignStep(
        scriptPubKey: BitcoinScript,
        ret: inout [Data],
        whichTypeRet: inout TransactionType,
        sigversion: SigVersion,
        sigdata: inout SignatureData
    ) -> Bool {
        var scriptRet = BitcoinScript(bytes: [])
        ret.removeAll()
        var sig = Data()

        var vSolutions = [Data]()
        if !solve(scriptPubKey: scriptPubKey, typeRet: &whichTypeRet, solutions: &vSolutions) {
            return false
        }

        switch whichTypeRet {
        case .nonstandard, .nullData, .witnessUnknown:
            return false
        case .pubkey:
            let address = BitcoinPublicKey(data: vSolutions[0])!.address.data
            if !createSig(sigdata: &sigdata, sig_out: &sig, keyid: address, scriptcode: scriptPubKey, sigversion: sigversion) {
                return false
            }
            ret.append(sig)
            return true
        case .pubkeyHash:
            let keyID = vSolutions[0]
            if !createSig(sigdata: &sigdata, sig_out: &sig, keyid: keyID, scriptcode: scriptPubKey, sigversion: sigversion) {
                return false
            }
            ret.append(sig)
            guard let pubkey = getPubKey(sigdata: &sigdata, address: keyID) else {
                return false
            }
            ret.append(pubkey.data)
            return true
        case .scriptHash:
            if let s = getScript(sigdata: sigdata, scriptid: vSolutions[0]) {
                scriptRet = s
                ret.append(Data(bytes: scriptRet.data))
                return true
            }
            return false

        case .multisig:
            let required = vSolutions.first![0]
            ret.append(Data()) // workaround CHECKMULTISIG bug
            for pubkeyData in vSolutions.dropFirst().dropLast() {
                let pubkey = BitcoinPublicKey(data: pubkeyData)
                if ret.count < required + 1 && createSig(sigdata: &sigdata, sig_out: &sig, keyid: pubkey!.address.data, scriptcode: scriptPubKey, sigversion: sigversion) {
                    ret.append(sig)
                }
            }
            let ok = ret.count == required + 1
            for _ in 0 ..< Int(required) + 1 - ret.count {
                ret.append(Data())
            }
            return ok
        case .witnessV0Keyhash:
            ret.append(vSolutions[0])
            return true

        case .witnessV0ScriptHash:
            var h160 = Data()
            let msgLen = UInt32(vSolutions[0].count)
            h160.withUnsafeMutableBytes { out in
                vSolutions[0].withUnsafeBytes { (msg: UnsafePointer<UInt8>) -> Void in
                    ripemd160(msg, msgLen, out)
                }
            }
            if let s = getScript(sigdata: sigdata, scriptid: h160) {
                scriptRet = s
                ret.append(Data(bytes: scriptRet.data))
                return true
            }
            return false
        }
    }

    func getScript(sigdata: SignatureData, scriptid: Data) -> BitcoinScript? {
        if let s = provider.getScript(scriptid: scriptid) {
            return s
        }

        // Look for scripts in SignatureData
        if let rscript = sigdata.redeem_script, Data(bytes: rscript.data) == scriptid {
            return rscript
        } else if let wscript = sigdata.witness_script, Data(bytes: wscript.data) == scriptid {
            return wscript
        }

        return nil
    }

    func solve(scriptPubKey: BitcoinScript, typeRet: inout TransactionType, solutions: inout [Data]) -> Bool {
        let WITNESS_V0_SCRIPTHASH_SIZE = 32
        let WITNESS_V0_KEYHASH_SIZE = 20

        solutions.removeAll()

        // Shortcut for pay-to-script-hash, which are more constrained than the other types:
        // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
        if scriptPubKey.isPayToScriptHash {
            typeRet = .scriptHash
            solutions.append(Data(bytes: scriptPubKey.data[2..<22]))
            return true
        }

        var witnessversion = 0
        var witnessprogram = Data()
        if scriptPubKey.isWitnessProgram(version: &witnessversion, program: &witnessprogram) {
            if witnessversion == 0 && witnessprogram.count == WITNESS_V0_KEYHASH_SIZE {
                typeRet = .witnessV0Keyhash
                solutions.append(witnessprogram)
                return true
            }
            if witnessversion == 0 && witnessprogram.count == WITNESS_V0_SCRIPTHASH_SIZE {
                typeRet = .witnessV0ScriptHash
                solutions.append(witnessprogram)
                return true
            }
            if witnessversion != 0 {
                typeRet = .witnessUnknown
                solutions.append(Data(bytes: [UInt8(witnessversion)]))
                solutions.append(witnessprogram)
                return true
            }
            typeRet = .nonstandard
            return false
        }

        // Provably prunable, data-carrying output
        //
        // So long as script passes the IsUnspendable() test and all but the first
        // byte passes the IsPushOnly() test we don't care what exactly is in the
        // script.
        var index = 1
        if scriptPubKey.data.count >= 1 && scriptPubKey.data[0] == OpCode.OP_RETURN && scriptPubKey.isPushOnly(at: &index) {
            typeRet = .nullData
            return true
        }

        if let pubkey = scriptPubKey.matchPayToPubkey() {
            typeRet = .pubkey
            solutions.append(pubkey.data)
            return true
        }

        if let pubkeyhash = scriptPubKey.matchPayToPubkeyHash() {
            typeRet = .pubkeyHash
            solutions.append(pubkeyhash)
            return true
        }

        var required = 0
        if let keys = scriptPubKey.matchMultisig(required: &required) {
            typeRet = .multisig
            solutions.append(Data(bytes: [UInt8(required)])) // safe as required is in range 1..16
            for key in keys {
                solutions.append(key.data)
            }
            solutions.append(Data(bytes: [UInt8(keys.count)])) // safe as size is in range 1..16
            return true
        }

        solutions.removeAll()
        typeRet = .nonstandard
        return false
    }

    func createSig(
        sigdata: inout SignatureData,
        sig_out: inout Data,
        keyid: Data,
        scriptcode: BitcoinScript,
        sigversion: SigVersion
    ) -> Bool {
        if let it = sigdata.signatures[keyid] {
            sig_out = it.1
            return true
        }
        guard let pubkey = getPubKey(sigdata: &sigdata, address: keyid) else {
            return false
        }
        guard let key = provider.getKey(address: keyid) else {
            return false
        }
        let signature = creator.createSig(scriptCode: scriptcode, version: sigversion, key: key)
        sigdata.signatures[keyid] = (pubkey, signature)
        return true
    }

    func getPubKey(sigdata: inout SignatureData, address: Data) -> BitcoinPublicKey? {
        if let pubkey = provider.getPubKey(address: address) {
            sigdata.misc_pubkeys[pubkey.address.data] = pubkey
            return pubkey
        }
        // Look for pubkey in all partial sigs
        if let it = sigdata.signatures[address] {
            return it.0
        }
        // Look for pubkey in pubkey list
        if let pk_it = sigdata.misc_pubkeys[address] {
            return pk_it
        }
        return nil
    }

    func PushAll(values: [Data]) -> BitcoinScript {
        let result = BitcoinScript(bytes: [])
        for v in values {
            if v.isEmpty {
                result.data.append(OpCode.OP_0)
            } else if v.count == 1 && v[0] >= 1 && v[0] <= 16 {
                result.data.append(BitcoinScript.encodeNumber(Int(v[0])))
            } else {
                result.data.append(contentsOf: Array(v))
            }
        }
        return result
    }

    struct SignatureData {
        var complete = false ///< Stores whether the scriptSig and scriptWitness are complete
        var witness = false ///< Stores whether the input this SigData corresponds to is a witness input
        var scriptSig: BitcoinScript ///< The scriptSig of an input. Contains complete signatures or the traditional partial signatures format
        var redeem_script: BitcoinScript? ///< The redeemScript (if any) for the input
        var witness_script: BitcoinScript? ///< The witnessScript (if any) for the input. witnessScripts are used in P2WSH outputs.
        var scriptWitness = BitcoinScriptWitness() ///< The scriptWitness of an input. Contains complete signatures or the traditional partial signatures format. scriptWitness is part of a transaction input per BIP 144.
        var signatures = [Data: (BitcoinPublicKey, Data)]() ///< BIP 174 style partial signatures for the input. May contain all signatures necessary for producing a final scriptSig or scriptWitness.
        var misc_pubkeys = [Data: BitcoinPublicKey]()

        init(scriptSig: BitcoinScript = BitcoinScript(bytes: [])) {
            self.scriptSig = scriptSig
        }

        // Extracts signatures and scripts from incomplete scriptSigs. Please do not extend this, use PSBT instead
        init(transaction tx: BitcoinTransaction, index: Int) {
            precondition(tx.inputs.count > index)
            scriptSig = tx.inputs[index].script
            scriptWitness = tx.inputs[index].scriptWitness
        }
    }
}

enum TransactionType {
    case nonstandard
    // 'standard' transaction types:
    case pubkey
    case pubkeyHash
    case scriptHash
    case multisig
    case nullData //!< unspendable OP_RETURN script that carries data
    case witnessV0ScriptHash
    case witnessV0Keyhash
    case witnessUnknown //!< Only for Witness versions not already defined above
}

protocol BaseSignatureCreator {
    /// Create a singular (non-script) signature.
    func createSig(scriptCode: BitcoinScript, version: SigVersion, key: PrivateKey) -> Data
}

final class TransactionSignatureCreator: BaseSignatureCreator {
    var transaction: BitcoinTransaction
    var index: Int
    var hashType: SignatureHashType
    var amount: Int64

    init(transaction: BitcoinTransaction, index: Int, amount: Int64, hashType: SignatureHashType) {
        self.transaction = transaction
        self.index = index
        self.amount = amount
        self.hashType = hashType
    }

    func createSig(scriptCode: BitcoinScript, version: SigVersion, key: PrivateKey) -> Data {
        let hash = transaction.getSignatureHash(scriptCode: scriptCode, index: index, hashType: hashType, amount: amount, sigversion: version)
        var signature = key.signAsDER(hash: hash)
        signature.append(UInt8(hashType.rawValue))
        return signature
    }
}

enum ScriptNumError: Error {
    case overflow
    case invalidEncoding
}

struct ScriptNum: Comparable {
    static let nDefaultMaxNumSize = 4
    var value: Int64

    /**
     * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
     * The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
     * but results may overflow (and are valid as long as they are not used in a subsequent
     * numeric operation). CScriptNum enforces those semantics by storing results as
     * an int64 and allowing out-of-range values to be returned as a vector of bytes but
     * throwing an exception if arithmetic is done or the result is interpreted as an integer.
     */
    init(_ n: Int64) {
        value = n
    }

    init(_ data: Data, fRequireMinimal: Bool, nMaxNumSize: Int = nDefaultMaxNumSize) throws {
        if data.count > nMaxNumSize {
            throw ScriptNumError.overflow
        }
        if fRequireMinimal && !data.isEmpty {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if (data.last! & 0x7f) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if data.count <= 1 || (data[data.count - 2] & 0x80) == 0 {
                    throw ScriptNumError.invalidEncoding
                }
            }
        }
        value = ScriptNum.decode(data)
    }

    static func == (lhs: ScriptNum, rhs: ScriptNum) -> Bool {
        return lhs.value == rhs.value
    }

    static func < (lhs: ScriptNum, rhs: ScriptNum) -> Bool {
        return lhs.value < rhs.value
    }

    func getint() -> Int {
        if value > Int.max {
            return Int.max
        } else if value < Int.min {
            return Int.min
        }
        return Int(value)
    }

    func encode() -> Data {
        return ScriptNum.encode(value)
    }

    static private func encode(_ value: Int64) -> Data {
        if value == 0 {
            return Data()
        }

        var result = Data()
        let neg = value < 0
        var absvalue = neg ? -value : value

        while absvalue != 0 {
            result.append(UInt8(absvalue & 0xff))
            absvalue >>= 8
        }

        //    - If the most significant byte is >= 0x80 and the value is positive, push a
        //    new zero-byte to make the significant byte < 0x80 again.

        //    - If the most significant byte is >= 0x80 and the value is negative, push a
        //    new 0x80 byte that will be popped off when converting to an integral.

        //    - If the most significant byte is < 0x80 and the value is negative, add
        //    0x80 to it, since it will be subtracted and interpreted as a negative when
        //    converting to an integral.

        if result.last! & 0x80 != 0 {
            result.append(neg ? 0x80 : 0)
        } else if neg {
            result[result.count - 1] |= 0x80
        }

        return result
    }

    static private func decode(_ vch: Data) -> Int64 {
        if vch.isEmpty {
            return 0
        }

        var result = 0 as Int64
        for i in 0 ..< vch.count {
            result |= Int64(vch[i]) << (8*i)
        }

        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if vch.last! & 0x80 != 0 {
            return -(Int64(result & ~(0x80 << (8 * (vch.count - 1)))))
        }

        return result
    }
}
