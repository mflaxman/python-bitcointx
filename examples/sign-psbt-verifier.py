# psbt CLI signer

from bitcointx import select_chain_params
from bitcointx.core import b2x, b2lx, lx, x 
from bitcointx.core.key import KeyStore, BIP32Path, BIP32PathTemplate, KeyDerivationInfo
from bitcointx.core.psbt import PartiallySignedTransaction
from bitcointx.base58 import Base58Error
from bitcointx.core.script import CScript, CScriptWitness

from bitcointx.wallet import CCoinKey, CCoinExtKey, CBitcoinAddress, P2WSHBitcoinAddress, CCoinAddress
select_chain_params('bitcoin/testnet')

TPRV = "tprv8ZgxMBicQKsPfNvyhJ8dmSzj1YMqaa52fxu7tmRNPmw8EhcUyjBr4KuTm6nVnicsDpBVhd9DBrsRvJEa9588423cEEh5faRq8rpig1fcBAb"
# xpriv format:
# xpriv = "xprv9s21ZrQH143K4ZhT2jH8boNjhQwdM432LQz12LzuuoSeT6sPzMr6YaY1qvcqnMEYrNeihXXT2WHdTSgq1rnBExn1hbUn1DhnDm5JEHbgscE"

INPUT_PSBT = "cHNidP8BAH0CAAAAAciw/6GsWeibtjKafG71WhOLT1L58drcunkkqMpmfTa2AAAAAAD/////AtISAAAAAAAAFgAU3RacollkleIxk+lz8my/mLCXiH2IEwAAAAAAACIAID6uagXJMRbXugC2BjPmcmp3A0VXA7vuUXe7D93tXAHsAAAAAAABASsQJwAAAAAAACIAIFOEACIAZIqKBYge/F4OwDI5N1aYtY52gasSzhGASjTsAQVHUSEDpsKKb7ofiMx37vD64ThCvgRV++c9AtRASF15OpQa27UhA8Pni0wHemy313UWoUfiA3lQoVhw86x2wf7zo+8qAL89Uq4iBgOmwopvuh+IzHfu8PrhOEK+BFX75z0C1EBIXXk6lBrbtRw6UrXNMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIgYDw+eLTAd6bLfXdRahR+IDeVChWHDzrHbB/vOj7yoAvz0cx9BkijAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAAAAQFHUSECNqbPQlTIKQoWjsq0rudxAY01fqhxVKW1/qntm67iWF4hA1XsEAHCxPHc4t6UC+rL3LfXdGFAKBqSgwAKpG0lHUYxUq4iAgI2ps9CVMgpChaOyrSu53EBjTV+qHFUpbX+qe2bruJYXhzH0GSKMAAAgAEAAIAAAACAAgAAgAEAAAAAAAAAIgIDVewQAcLE8dzi3pQL6svct9d0YUAoGpKDAAqkbSUdRjEcOlK1zTAAAIABAACAAAAAgAIAAIABAAAAAAAAAAA="


# TODO: make into verbose flag 
VERBOSE = True

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
    address = CCoinAddress.from_scriptPubKey(unsigned_tx.vout[idx].scriptPubKey)
    output_desc = {
        "sats": unsigned_tx.vout[idx].nValue,
        # Use CCoinAddress (instead of CBitcoinAddress) because of testnet
        "addr": str(address),
        "addr_type": address.__class__.__name__,
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

# change is optional (sweep) but spend is not:
assert spend_addr, psbt
assert output_spend_sats, psbt        

# INP_AMOUNT = sum([inp.get_amount(self.unsigned_tx) for inp in unsigned_tx.vin])
# OUT_AMOUNT = sum([outp.nValue for outp in self.unsigned_tx.vout])

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
    "(", round(psbt.get_fee() / output_spend_sats * 100, 2), "%)",
    "and txid",
    b2lx(unsigned_tx.GetTxid()),
    "\n",
)


inputs_desc = []
for idx, inp in enumerate(unsigned_tx.vin):
    # FIXME: ammounts available in PSBT (shouldn't segwit amounts be signed?)
    inputs_desc.append({
        "prev_txhash": b2lx(inp.prevout.hash),
        "prev_idx": inp.prevout.n,
        "amount": psbt.inputs[idx].get_amount(unsigned_tx=unsigned_tx),
        # "addr": "",  # TODO: possible to get this info?
    })

if VERBOSE:
    print(len(inputs_desc), "input(s):")
    for input_desc in inputs_desc:
        print("", input_desc)
    print(len(outputs_desc), "output(s):")
    for output_desc in outputs_desc:
        print("", output_desc)

ks = KeyStore.from_iterable(
    # xpriv with no mainet selected also works
    iterable=[XPRIV_TO_USE, ],
    # "m/48h/1h/0h/2h/0/0" (notice the change/index stuff is messy)
    default_path_template=None,
    require_path_templates=False,
)
sign_result = psbt.sign(ks, finalize=False)

print("")
print("PSBT with added signature:")
print(psbt.to_base64())

# FIXME: add these safety checks:
if False:
    print("")
    print(f'Transaction has total {len(psbt.inputs)} inputs\n')
    print(f'Added signatures to {sign_result.num_inputs_signed} inputs')
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


    import pdb; pdb.set_trace()
    print()
    if args.finalize:
        if not sign_result.is_final:
            print(f'Failed to finalize transaction')
            sys.exit(-1)

        print("Signed network transaction:\n")
        print(b2x(psbt.extract_transaction().serialize()))
    elif sign_result.num_inputs_signed == 0:
        print("Could not sign any inputs")
        sys.exit(-1)
    else:
        print("PSBT with added signatures:\n")
        print(psbt.to_base64())
