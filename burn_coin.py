#! /usr/bin/env python

import sys, string
from OP_RETURN import OpReturn, hex_to_bin


if len(sys.argv)<4:
    sys.exit(
'''Usage:
python burn_coin.py <coinname> <burn-amount> <metadata> <testnet (optional)>

Examples:
python burn_coin.py bitcoin 0.001 'Hello, blockchain!'
python burn_coin.py ppcoin 0.001 48656c6c6f2c20626c6f636b636861696e21
python burn_coin.py MudCoin 0.001 'Hello, testnet blockchain!' 1'''
    )

dummy, coin_name, burn_amount, metadata = sys.argv[0:4]
if len(sys.argv)>4:
    testnet=bool(sys.argv[4])
else:
    testnet=False

opreturn = OpReturn(coin_name, testnet)
metadata_from_hex = hex_to_bin(metadata)
if metadata_from_hex is not None:
    metadata = metadata_from_hex

result = opreturn.burn(float(send_amount), metadata)
if 'error' in result:
    print('Error: '+result['error'])
else:
    print('TxID: '+result['txid']+'\n')

# vim:ts=4:sw=4:ai:et:si:sts=4
