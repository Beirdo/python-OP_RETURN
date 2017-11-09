#! /usr/bin/env python

import os
import sys
import string
import argparse
import logging

from OP_RETURN import OpReturn, hex_to_bin

logger = logging.getLogger(__name__)

def setupLogging(verbose=False, quiet=False):
    fileFormat = "%(asctime)s: %(name)s (%(threadName)s) %(filename)s:%(lineno)d [%(levelname)s] - %(message)s"
    fileFormatter = logging.Formatter(fileFormat)
    logFile = os.path.join("~/.cleanup", "defrag.log")
    logFile = os.path.expanduser(logFile)
    fileHandler = logging.FileHandler(logFile, "a")
    fileHandler.setFormatter(fileFormatter)
    fileHandler.setLevel(logging.DEBUG)

    if not quiet:
        level = logging.DEBUG if verbose else logging.INFO

        consoleFormat = "%(asctime)s: %(name)s [%(levelname)s] - %(message)s"
        consoleFormatter = logging.Formatter(consoleFormat)
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(consoleFormatter)
        consoleHandler.setLevel(level)

    rootLogger = logging.getLogger(None)
    rootLogger.addHandler(fileHandler)
    if not quiet:
        rootLogger.addHandler(consoleHandler)
    rootLogger.setLevel(logging.DEBUG)

def main():
    parser = argparse.ArgumentParser(description="Burn coins")
    parser.add_argument('--verbose', '-v', action="store_true",
                        help="Turn on debug logging")
    parser.add_argument('--quiet', '-q', action="store_true",
                        help="Shut off console logging")
    parser.add_argument('--dryrun', '-n', action="store_true",
                        help="Do not submit transaction")
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
    parser.add_argument('--min-confirmations', '-C', type=int, default=100,
                        help='Minimum confirmations')
    parser.add_argument('--max-confirmations', '-D', type=int,
                        help='Maximum confirmations')
    parser.add_argument('--max-amount', '-A', type=float,
                        help="Maximum amount of coin per input")
    args = parser.parse_args()

    setupLogging(args.verbose, args.quiet)

    logger.info("Defragging %s, Sending to %s" % (args.coin, args.to))
    logger.info("max inputs: %s, base fee: %s, min confirms: %s, max confirms: %s" %
                (args.max_tx, args.fee, args.min_confirmations,
                 args.max_confirmations))
    if args.max_amount:
        logger.info("Max amount per input: %s" % args.max_amount)

    if args.amount:
        logger.info("max amount to send: %s" % args.amount)
    else:
        logger.info("No max amount")

    opreturn = OpReturn(args.coin, args.testnet, args.digits, args.use_message,
                        args.fee, args.min_confirmations,
                        args.max_confirmations)

    result = opreturn.defrag_send(args.to, args.amount, args.max_tx,
                                  args.max_amount, args.dryrun)
    if not result:
        logger.info('No transaction made, no inputs available')
    elif 'error' in result:
        logger.error('Error: %s' % result['error'])
        return 1
    else:
        logger.info('TxID: %s' % result['txid'])

    return 0

if __name__ == "__main__":
    sys.exit(main())

# vim:ts=4:sw=4:ai:et:si:sts=4
