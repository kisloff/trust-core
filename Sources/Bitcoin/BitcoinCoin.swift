// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

/// A UTXO entry.
///
/// Serialized format:
///   - VARINT((coinbase ? 1 : 0) | (height << 1))
///   - the non-spent CTxOut (via CTxOutCompressor)
public struct BitcoinCoin {
    /// unspent transaction output
    public var out: BitcoinTransactionOutput

    /// whether containing transaction was a coinbase
    public var coinBase: Bool

    /// at which height this containing transaction was included in the active block chain
    public var height: UInt32

    public init() {
        out = BitcoinTransactionOutput()
        coinBase = false
        height = 0
    }

    /// construct a Coin from a CTxOut and height/coinbase information.
    public init(out: BitcoinTransactionOutput, height: UInt32, coinBase: Bool) {
        self.out = out
        self.height = height
        self.coinBase = coinBase
    }

    public mutating func clear() {
        out.script.data.removeAll()
        out.value = -1
        out.script.bytes = []
        coinBase = false
        height = 0
    }

    public var isSpent: Bool {
        return out.isNull
    }
}
