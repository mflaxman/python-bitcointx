# psbt CLI signer

from bitcointx import select_chain_params
from bitcointx.core import b2x, b2lx, lx, x 
from bitcointx.core.key import KeyStore, BIP32Path, BIP32PathTemplate, KeyDerivationInfo
from bitcointx.core.psbt import PartiallySignedTransaction
from bitcointx.base58 import Base58Error
from bitcointx.core.script import CScript, CScriptWitness

from bitcointx.wallet import CCoinKey, CCoinExtKey, CBitcoinAddress, P2WSHBitcoinAddress, CCoinAddress

import os 

select_chain_params('bitcoin/testnet')

TPRV = os.environ.get("TPRV", "tprv8ZgxMBicQKsPfNvyhJ8dmSzj1YMqaa52fxu7tmRNPmw8EhcUyjBr4KuTm6nVnicsDpBVhd9DBrsRvJEa9588423cEEh5faRq8rpig1fcBAb")
# xpriv format:
# xpriv = "xprv9s21ZrQH143K4ZhT2jH8boNjhQwdM432LQz12LzuuoSeT6sPzMr6YaY1qvcqnMEYrNeihXXT2WHdTSgq1rnBExn1hbUn1DhnDm5JEHbgscE"

INPUT_PSBT = os.environ["INPUT_PSBT"]
LIVE_DANGEROUSLY = bool(os.environ.get("LIVE_DANGEROUSLY", False))

print()

if LIVE_DANGEROUSLY:
    print("-"*80)
    print("WARNING: LIVE_DANGEROUSLY flag is set, some safety checks disabled")
    print("-"*80)

VERBOSE = bool(os.environ.get("VERBOSE", True))

###

psbt = PartiallySignedTransaction.from_base64_or_binary(INPUT_PSBT)
unsigned_tx = psbt.unsigned_tx

XPRIV_TO_USE = CCoinExtKey(TPRV)

# FIXME: validation:
# 1. input xfps haven't changed from input to outputs
# 2. we have the privkey for each change addr 
# 3. FUTURE: that each amount in the inputs is correct (segwit should handle this but confirm library implemenation)


# safety checks
assert len(psbt.inputs) ==  len(unsigned_tx.vin), psbt
assert len(psbt.outputs) ==  len(unsigned_tx.vout), psbt
# right now we only cover sweeps and spend + change use-case
assert 1 <= len(psbt.outputs) <= 2, psb.outputs
# TODO assert p2wsh only

spend_addr, change_addr = "", ""
output_spend_sats = 0
output_change_sats = 0
outputs_desc = []
for idx, output in enumerate(psbt.outputs):
    addr_obj = CCoinAddress.from_scriptPubKey(unsigned_tx.vout[idx].scriptPubKey)
    output_desc = {
        # TODO: no way to verify this from psbt itself? seems like a bug:
        "sats": unsigned_tx.vout[idx].nValue,
        # Use CCoinAddress (instead of CBitcoinAddress) because of testnet:
        "addr": str(addr_obj),
        "addr_type": addr_obj.__class__.__name__,
        "is_change": False,
    }
    if output.derivation_map:
        # this is the change, let's validate it
        is_valid_change = False
        for k, v in output.derivation_map.items():
            # iterate through all the xpubs/paths in this change output
            if v.master_fp.hex() == XPRIV_TO_USE.fingerprint.hex():
                # TODO: use v (PSBT_KeyDerivationInfo(x('3a52b5cd'), BIP32Path("m/48'/1'/0'/2'/1/0"))) to validate we have the key
                output_desc['is_change'] = True
                output_change_sats += unsigned_tx.vout[idx].nValue
                change_addr = output_desc['addr']
                
        assert output_desc['is_change'] is True, output

    else:
        # Use CCoinAddress (instead of CBitcoinAddress) because of testnet
        spend_addr = output_desc['addr']
        output_spend_sats += unsigned_tx.vout[idx].nValue
        
    outputs_desc.append(output_desc)

# Currently only supporting TXs with 1-2 outputs (sweep TX OR spend+change TX):
assert 1 <= len(outputs_desc) <= 2, outputs_desc

# change is optional (sweep) but spend is not:
if not LIVE_DANGEROUSLY:
    err_msg = "Transaction missing spend address/ammount, are you doing a sweep to yourself? Set LIVE_DANGEROUSLY to ignore this error."
    assert spend_addr and output_spend_sats, err_msg

if VERBOSE:
    print("PSBT Before Signing:")
    print(INPUT_PSBT, "\n")

# TODO: better fee confirmation
print(
    "Sending",
    output_spend_sats,
    "sats to",
    spend_addr,
    "with a fee of",
    psbt.get_fee(),
    "(" + round(psbt.get_fee() / output_spend_sats * 100, 2) + "% )" if output_spend_sats else "",
    "with txid",
    b2lx(unsigned_tx.GetTxid()),
    "\n",
)


inputs_desc = []
for idx, unsigned_inp in enumerate(unsigned_tx.vin):
    psbt_inp = psbt.inputs[idx]
    addr_obj = CCoinAddress.from_scriptPubKey(psbt_inp.witness_script.to_p2wsh_scriptPubKey())
    inputs_desc.append({
        # From Unsigned TX
        "prev_txhash": b2lx(unsigned_inp.prevout.hash),
        "prev_idx": unsigned_inp.prevout.n,
        "n_sequence": unsigned_inp.nSequence,
        # From PSBT:
        "addr": str(addr_obj),
        "addr_type": addr_obj.__class__.__name__,
        # TODO: confirm amounts only available in PSBT (not unsiged_tx) + that segwit amounts are being signed
        "sats": psbt_inp.get_amount(unsigned_tx=unsigned_tx),
        "witness_script": psbt_inp.witness_script,
    })

if VERBOSE:
    print("-"*80)
    print("DETAILED VIEW")
    print(len(inputs_desc), "input(s):")
    for input_desc in inputs_desc:
        print("", input_desc)
    print(len(outputs_desc), "output(s):")
    for output_desc in outputs_desc:
        print("", output_desc)
    print("-"*80)

ks = KeyStore.from_iterable(
    # xpriv with no mainet selected also works
    iterable=[XPRIV_TO_USE, ],
    # "m/48h/1h/0h/2h/0/0" (notice the change/index stuff is messy)
    default_path_template=None,
    require_path_templates=False,
)
sign_result = psbt.sign(ks, finalize=False)

# Confirm we were able to sign all inputs
assert sign_result.num_inputs_signed == len(psbt.inputs), psbt

num_missing_sigs_per_input = []
for index, info in enumerate(sign_result.inputs_info):
    assert info, psbt
    # Confirm signing worked (should have added 1 new sig):
    assert info.num_new_sigs == 1, info
    num_missing_sigs_per_input.append(info.num_sigs_missing)

assert all(x == num_missing_sigs_per_input[0] for x in num_missing_sigs_per_input), "Different number of sigs needed per input"


print("")
print("PSBT with added signature:")
print(psbt.to_base64())

# FIXME: add these safety checks:
if False:
    print(f'{sign_result.num_inputs_final} inputs is finalized')
    if not sign_result.is_final:
        print(f'{sign_result.num_inputs_ready} inputs is ready '
              f'to be finalized\n')
    else:
        assert sign_result.num_inputs_ready == 0

    if not sign_result.is_final and sign_result.num_inputs_signed > 0:
        for index, info in enumerate(sign_result.inputs_info):
            if info:
                print(f"Input {index}: added {info.num_new_sigs} sigs, ",
                      end='')
                print(f"input is now final"
                      if info.is_final
                      else f"{info.num_sigs_missing} is still missing")
            else:
                print(f"Input {index}: skipped, cannot be processed")


    if args.finalize:
        if not sign_result.is_final:
            print(f'Failed to finalize transaction')
            sys.exit(-1)

        print("Signed network transaction:\n")
        print(b2x(psbt.extract_transaction().serialize()))
