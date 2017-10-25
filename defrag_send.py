#! /usr/bin/env python

import sys
import string
import argparse

from OP_RETURN import OpReturn, hex_to_bin

parser = argparse.ArgumentParser(description="Burn coins")
parser.add_argument('--coin', '-c', required=True, help="Coin name")
parser.add_argument('--amount', '-a', required=True, type=float,
                    help="Amount of coin to burn")
parser.add_argument('--to', '-t', required=True, help="Address to send to")
parser.add_argument('--testnet', '-T', action='store_true',
                    help="Use testnet rather than mainnet")
parser.add_argument('--digits', '-d', type=float, default=8,
                    help="Digits to right of . (bitcoin=8, peercoin=6)")
parser.add_argument('--no-message', '-M', action='store_false',
                    dest="use_message", help="Disable txn message")
parser.add_argument('--max-tx', '-m', type=int, default=0,
                    help="Maximum number of input transactions")
parser.add_argument('--fee', '-f', type=float, help='TX Fees')
parser.add_argument('--confirmations', '-C', type=int, default=100,
                    help='Minimum confirmations')
args = parser.parse_args()

opreturn = OpReturn(args.coin, args.testnet, args.digits, args.use_message,
                    args.fee, args.confirmations)

result = opreturn.defrag_send(args.to, args.amount, args.max_tx)
if 'error' in result:
    print('Error: %s' % result['error'])
else:
    print('TxID: %s' % result['txid'])

# vim:ts=4:sw=4:ai:et:si:sts=4
