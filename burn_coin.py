#! /usr/bin/env python

import sys
import string
import argparse

from OP_RETURN import OpReturn, hex_to_bin

parser = argparse.ArgumentParser(description="Burn coins")
parser.add_argument('--coin', '-c', required=True, help="Coin name")
parser.add_argument('--amount', '-a', required=True, type=float,
                    help="Amount of coin to burn")
parser.add_argument('--message', '-m', default="Burning coin",
                    help="Message to embed in transaction")
parser.add_argument('--testnet', '-T', action='store_true',
                    help="Use testnet rather than mainnet")
args = parser.parse_args()

if args.amount <= 0.0:
    print("Invalid burn amount (> 0.0)")
    sys.exit(1)

if not args.message:
    args.message = "Burning coin"

opreturn = OpReturn(args.coin, args.testnet)
metadata_from_hex = hex_to_bin(args.message)
if metadata_from_hex is not None:
    args.message = metadata_from_hex

result = opreturn.burn(args.amount, args.message)
if 'error' in result:
    print('Error: %s' % result['error'])
else:
    print('TxID: %s' % result['txid'])

# vim:ts=4:sw=4:ai:et:si:sts=4
