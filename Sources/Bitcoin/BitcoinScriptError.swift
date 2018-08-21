// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

enum ScriptError {
    case UNKNOWN_ERROR
    case EVAL_FALSE
    case OP_RETURN

    /* Max sizes */
    case SCRIPT_SIZE
    case PUSH_SIZE
    case OP_COUNT
    case STACK_SIZE
    case SIG_COUNT
    case PUBKEY_COUNT

    /* Failed verify operations */
    case SCRIPT_ERR_VERIFY
    case EQUALVERIFY
    case CHECKMULTISIGVERIFY
    case CHECKSIGVERIFY
    case NUMEQUALVERIFY

    /* Logical/Format/Canonical errors */
    case SCRIPT_ERR_BAD_OPCODE
    case DISABLED_OPCODE
    case INVALID_STACK_OPERATION
    case INVALID_ALTSTACK_OPERATION
    case UNBALANCED_CONDITIONAL

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    case SCRIPT_ERR_NEGATIVE_LOCKTIME
    case UNSATISFIED_LOCKTIME

    /* Malleability */
    case SCRIPT_ERR_SIG_HASHTYPE
    case SIG_DER
    case MINIMALDATA
    case SIG_PUSHONLY
    case SIG_HIGH_S
    case SIG_NULLDUMMY
    case PUBKEYTYPE
    case CLEANSTACK
    case MINIMALIF
    case SIG_NULLFAIL

    /* softfork safeness */
    case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS
    case DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM

    /* segregated witness */
    case SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH
    case WITNESS_PROGRAM_WITNESS_EMPTY
    case WITNESS_PROGRAM_MISMATCH
    case WITNESS_MALLEATED
    case WITNESS_MALLEATED_P2SH
    case WITNESS_UNEXPECTED
    case WITNESS_PUBKEYTYPE

    /* Constant scriptCode */
    case SCRIPT_ERR_OP_CODESEPARATOR
    case SIG_FINDANDDELETE

    case SCRIPT_ERR_ERROR_COUNT
}
