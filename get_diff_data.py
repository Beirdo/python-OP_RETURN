#! /usr/bin/env python

import os
import sys
import string
import argparse
import logging
import json

from OP_RETURN import OpReturn, hex_to_bin

logger = logging.getLogger(__name__)

def setupLogging(verbose=False, quiet=False):
    fileFormat = "%(asctime)s: %(name)s (%(threadName)s) %(filename)s:%(lineno)d [%(levelname)s] - %(message)s"
    fileFormatter = logging.Formatter(fileFormat)
    logFile = os.path.join("~/.cleanup", "diff_data.log")
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
    args = parser.parse_args()

    setupLogging(args.verbose, args.quiet)

    logger.info("Getting POW difficulty data for  %s" % args.coin)

    opreturn = OpReturn(args.coin)

    getinfo = opreturn.bitcoin_cmd('getinfo')
    numBlocks = getinfo.get('blocks', 0)

    logger.info("Total blocks: %s" % numBlocks)

    data = []
    for block in range(1, numBlocks):
        blockhash = opreturn.bitcoin_cmd('getblockhash', block)
        blockdata = opreturn.bitcoin_cmd('getblock', blockhash)
        data.append(blockdata)

    with open("diffdata-%s.json" % args.coin, "w") as f:
        json.dump(data, f, sort_keys=True, indent=2)

    timedata = []
    for blockdata in data:
        item = [blockdata.get("time", 0), blockdata.get('difficulty', 0.0),
                blockdata.get('entropybit', 0)]
        timedata.append(item)

    with open("timedata-%s.json" % args.coin, "w") as f:
        json.dump(data, f, sort_keys=True, indent=2)

    return 0

if __name__ == "__main__":
    sys.exit(main())

# vim:ts=4:sw=4:ai:et:si:sts=4