#! /usr/bin/env python

import sys
import string
import argparse

from OP_RETURN import OpReturn, hex_to_bin

parser = argparse.ArgumentParser(description="Burn coins")
parser.add_argument('--coin', '-c', required=True, help="Coin name")
parser.add_argument('--testnet', '-T', action='store_true',
                    help="Use testnet rather than mainnet")
parser.add_argument('--file', '-f', required=True, help="Transaction to send")
args = parser.parse_args()

opreturn = OpReturn(args.coin, args.testnet)
with open(args.file, "r") as f:
    txn = f.read().strip()

result = opreturn.send_txn(txn)
if 'error' in result:
    print('Error: %s' % result['error'])
else:
    print('TxID: %s' % result['txid'])

# vim:ts=4:sw=4:ai:et:si:sts=4
