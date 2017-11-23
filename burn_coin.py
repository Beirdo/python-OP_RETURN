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
    logFile = os.path.join("~/.cleanup", "burn.log")
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
    parser.add_argument('--coin', '-c', required=True, help="Coin name")
    parser.add_argument('--amount', '-a', required=True, type=float,
                        help="Amount of coin to burn")
    parser.add_argument('--message', '-M', default="Burning coin",
                        help="Message to embed in transaction")
    parser.add_argument('--testnet', '-T', action='store_true',
                        help="Use testnet rather than mainnet")
    parser.add_argument('--digits', '-d', type=float, default=8,
                        help="Digits to right of . (bitcoin=8, peercoin=6)")
    parser.add_argument('--no-message', '-N', action='store_false',
                        dest="use_message", help="Disable txn message")
    parser.add_argument('--max-tx', '-m', type=int, default=0,
                        help="Maximum number of input transactions")
    parser.add_argument('--fee', '-f', type=float, help='TX Fees')
    parser.add_argument('--dryrun', '-n', action="store_true",
                        help="Do not submit transaction")
    parser.add_argument('--min-confirmations', '-C', type=int, default=100,
                        help='Minimum confirmations')
    parser.add_argument('--max-confirmations', '-D', type=int,
                        help='Maximum confirmations')
    args = parser.parse_args()

    setupLogging(args.verbose, args.quiet)

    if args.amount <= 0.0:
        logger.error("Invalid burn amount (%s)" % args.amount)
        sys.exit(1)

    if not args.message:
        args.message = "Burning coin"

    logger.info("Burning %s" % args.coin)
    logger.info("max input count: %s, base fee: %s" %
                (args.max_tx, args.fee))
    logger.info("min confirms: %s, max confirms: %s" %
                (args.min_confirmations, args.max_confirmations))

    logger.info("amount to burn: %s" % args.amount)

    opreturn = OpReturn(args.coin, args.testnet, args.digits, args.use_message,
                        args.fee, args.min_confirmations,
                        args.max_confirmations)
    metadata_from_hex = hex_to_bin(args.message)
    if metadata_from_hex is not None:
        args.message = metadata_from_hex

    result = opreturn.burn(args.amount, args.message, args.dryrun)
    if not result:
        logger.info('No transaction made, no inputs available')
    elif 'error' in result:
        logger.error('Error: %s' % result['error'])
    else:
        logger.info('TxID: %s' % result['txid'])

if __name__ == "__main__":
    sys.exit(main())

# vim:ts=4:sw=4:ai:et:si:sts=4
