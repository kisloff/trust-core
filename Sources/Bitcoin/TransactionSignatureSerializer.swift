// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// Wrapper that serializes like `BitcoinTransaction`, but with the modifications required for the signature hash done in-place
final class TransactionSignatureSerializer {
    /// reference to the spending transaction (the one being serialized)
    var transaction: BitcoinTransaction

    /// output script being consumed
    var scriptCode: BitcoinScript

    /// input index of txTo being signed
    var index: Int

    /// whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    var anyoneCanPay: Bool

    /// whether the hashtype is SIGHASH_SINGLE
    var hashSingle: Bool

    /// whether the hashtype is SIGHASH_NONE
    var hashNone: Bool

    init(transaction: BitcoinTransaction, scriptCodeIn: BitcoinScript, index: Int, hashType: SignatureHashType) {
        self.transaction = transaction
        self.scriptCode = scriptCodeIn
        self.index = index
        self.anyoneCanPay = hashType.contains(.anyoneCanPay)
        self.hashSingle = hashType.single
        self.hashNone = hashType.none
    }

    /// Serialize txTo
    func serialize(into data: inout Data) {
        // Serialize nVersion
        transaction.version.encode(into: &data)

        // Serialize inputs
        let nInputs = anyoneCanPay ? 1 : transaction.inputs.count
        writeCompactSize(nInputs, into: &data)
        for i in 0 ..< nInputs {
            serializeInput(into: &data, nInput: i)
        }

        // Serialize outputs
        let nOutputs = hashNone ? 0 : (hashSingle ? index+1 : transaction.outputs.count)
        writeCompactSize(nOutputs, into: &data)
        for i in 0 ..< nOutputs {
            serializeOutput(into: &data, nOutput: i)
        }

        // Serialize lockTime
        transaction.lockTime.encode(into: &data)
    }

    /// Serialize an input of txTo
    private func serializeInput(into data: inout Data, nInput: Int) {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        var inputCount = nInput
        if anyoneCanPay {
            inputCount = index
        }

        // Serialize the prevout
        transaction.inputs[inputCount].previousOutput.encode(into: &data)

        // Serialize the script
        if inputCount != index {
            // Blank out other inputs' signatures
            Data().encode(into: &data)
        } else {
            serializeScriptCode(into: &data)
        }

        // Serialize the nSequence
        if inputCount != index && (hashSingle || hashNone) {
            // let the others update at will
            0.encode(into: &data)
        } else {
            transaction.inputs[inputCount].sequence.encode(into: &data)
        }
    }

    /// Serialize the passed scriptCode, skipping OP_CODESEPARATORs
    private func serializeScriptCode(into data: inout Data) {
        var it = scriptCode.data.startIndex
        var itBegin = it
        var opcode = 0 as UInt8
        var nCodeSeparators = 0
        var contents = Data()

        while scriptCode.getScriptOp(index: &it, opcode: &opcode, contents: &contents) {
            if opcode == OpCode.OP_CODESEPARATOR {
                nCodeSeparators += 1
            }
        }
        writeCompactSize(scriptCode.data.count - nCodeSeparators, into: &data)
        it = itBegin
        while scriptCode.getScriptOp(index: &it, opcode: &opcode, contents: &contents) {
            if opcode == OpCode.OP_CODESEPARATOR {
                data.append(scriptCode.data[itBegin ..< it - 1])
                itBegin = it
            }
        }
        if itBegin != scriptCode.data.endIndex {
            data.append(scriptCode.data[itBegin ..< it])
        }
    }

    /// Serialize an output of txTo
    private func serializeOutput(into data: inout Data, nOutput: Int) {
        if hashSingle && nOutput != index {
            // Do not lock-in the txout payee at other indices as txin
            BitcoinTransactionOutput().encode(into: &data)
        } else {
            transaction.outputs[nOutput].encode(into: &data)
        }
    }
}
