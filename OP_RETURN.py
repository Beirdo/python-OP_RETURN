# OP_RETURN.py
#
# Python script to generate and retrieve OP_RETURN bitcoin transactions
#
# Copyright (c) 2015 Coin Sciences Ltd
# Copyright (c) 2017 Gavin Hurlbut <gjhurlbu@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import json
import time
import random
import os
import binascii
import struct
import string
import re
import hashlib
import base58
import requests
import logging

# Python 2-3 compatibility logic

try:
    basestring
except NameError:
    basestring = str

logger = logging.getLogger(__name__)

class OpReturn:
    ip = '127.0.0.1' # IP address of your bitcoin node
    txfee = 0.0001   # Transaction fee
    dust = 0.00001   # omit outputs smaller than this
    maxBytes = 80    # maximum bytes in an OP_RETURN (80 as of Bitcoin 0.11)
    maxBlocks = 10   # maximum number of blocks to try when retrieving data
    timeout = 10     # timeout (in s) when communicating with node

    def __init__(self, coin_name, testnet=False, digits=8, use_message=True,
                 txfee=None, min_confirmations=None, max_confirmations=None):
        self.testnet = testnet
        self.coin_name = coin_name
        self.digits = digits
        self.use_message = use_message
        conffile = os.path.join('~', '.%s' % coin_name, '%s.conf' % coin_name)
        self.config_file = os.path.expanduser(conffile)

        with open(self.config_file, "r") as f:
            lines = f.readlines()

        config = dict([line.strip().split('=', 1) for line in lines])
        self.port = int(config.get('rpcport', 0))
        self.user = config.get('rpcuser', None)
        self.password = config.get('rpcpassword', None)

        if not self.port or not self.user or not self.password:
            raise Exception("No usable RPC setup in %s" % self.config_file)

        self.url = 'http://%s:%s/' % (self.ip, self.port)
        self.session = requests.Session()
        self.session.auth = (self.user, self.password)
        self.session.timeout = self.timeout
        if txfee is not None:
            self.txfee = float(txfee)
        self.min_confirmations = 0
        self.max_confirmations = 1000000000
        if min_confirmations is not None:
            self.min_confirmations = int(min_confirmations)
        if max_confirmations is not None:
            self.max_confirmations = int(max_confirmations)

    def burn(self, burn_amount, metadata):
        # Validate some parameters
        err = self.bitcoin_check()
        if err:
            return error_(err)

        if isinstance(metadata, basestring):
            metadata = metadata.encode('utf-8') # convert to binary string

        metadata_len = len(metadata)

        if metadata_len > self.maxBytes:
            return error_('Metadata has %s bytes but is limited to %s (see self.maxBytes)' % (metadata_len, self.maxBytes))

        if metadata_len > 65535:
            return error_('This library only supports metadata up to 65535 bytes in size')

        # Calculate amounts and choose inputs
        output_amount = burn_amount + self.txfee

        inputs_spend = self.select_inputs(output_amount)
        err = inputs_spend.get('error', None)
        if err:
            return error_(err)

        change_amount = inputs_spend['total'] - output_amount

        # Build the raw transaction
        outputs = {
            "burn": burn_amount,
        }

        if change_amount >= self.dust:
            change_address = self.bitcoin_cmd('getaccountaddress', 'change')
            outputs[change_address] = change_amount

        raw_txn = self.create_burn_txn(inputs_spend['inputs'], outputs,
                                       metadata)

        # Sign and send the transaction, return result
        return self.sign_send_txn(raw_txn)

    def estimate_fee(self, inputs):
        # Estimate
        txsize = inputs['count'] * 41 + 100
        txfee = int(1 + int(txsize / 10000.0)) * self.txfee
        logger.info("Estimated fees: %s" % txfee)
        return txfee

    def defrag_send(self, send_address, send_amount, max_count=None,
                    max_amount=None, dryrun=None):
        # Validate some parameters
        err = self.bitcoin_check()
        if err:
            return error_(err)

        result = self.bitcoin_cmd('validateaddress', send_address)
        invalid = result.get('invalid', False)
        if invalid:
            return error_('Send address could not be validated: %s' %
                          send_address)

        if send_amount <= 0.0:
            inputs_spend = self.select_all_inputs(send_address, max_count,
                                                  max_amount)
            err = inputs_spend.get('error', None)
            if err:
                return error_(err)
            output_amount = inputs_spend['total']
            send_amount = output_amount - self.estimate_fee(inputs_spend)
        else:
            # Calculate amounts and choose inputs
            output_amount = send_amount + 10.0
            inputs_spend = self.select_inputs(output_amount, send_address,
                                              max_amoun)

            err = inputs_spend.get('error', None)
            if err:
                return error_(err)
            output_amount = send_amount + self.estimate_fee(inputs_spend)

        change_amount = inputs_spend['total'] - output_amount

        # Build the raw transaction
        outputs = {send_address: send_amount}

        if change_amount >= self.dust:
            change_address = self.bitcoin_cmd('getaccountaddress', 'change')
            outputs[change_address] = change_amount

        logger.debug("Inputs to spend: %s" % inputs_spend)
        logger.info("Number of inputs selected: %s" % inputs_spend['count'])
        logger.info("Output Amount: %.8f" % output_amount)
        if change_amount:
            logger.info("Change Amount: %.8f" % change_amount)
        if not inputs_spend['count']:
            return None

        logger.debug("Outputs: %s" % outputs)
            
        raw_txn = self.bitcoin_cmd('createrawtransaction',
                                   inputs_spend['inputs'], outputs)

        # Sign and send the transaction, return result
        if not dryrun:
            return self.sign_send_txn(raw_txn)
        return None

    def send(self, send_address, send_amount, metadata):
        # Validate some parameters
        err = self.bitcoin_check()
        if err:
            return error_(err)

        result = self.bitcoin_cmd('validateaddress')
        invalid = result.get('invalid', False)
        if invalid:
            return error_('Send address could not be validated: %s' %
                          send_address)

        if isinstance(metadata, basestring):
            metadata = metadata.encode('utf-8') # convert to binary string

        metadata_len = len(metadata)

        if metadata_len > self.maxBytes:
            return error_('Metadata has %s bytes but is limited to %s (see self.maxBytes)' % (metadata_len, self.maxBytes))

        if metadata_len > 65535:
            return error_('This library only supports metadata up to 65535 bytes in size')

        # Calculate amounts and choose inputs
        output_amount = send_amount + self.txfee
        inputs_spend = self.select_inputs(output_amount)

        err = inputs_spend.get('error', None)
        if err:
            return error_(err)

        change_amount = inputs_spend['total'] - output_amount

        # Build the raw transaction
        outputs={
            send_address: send_amount
        }

        if change_amount >= self.dust:
            change_address = self.bitcoin_cmd('getaccountaddress', 'change')
            outputs[change_address] = change_amount
            
        raw_txn = self.create_txn(inputs_spend['inputs'], outputs, metadata,
                                  len(outputs))

        # Sign and send the transaction, return result
        return self.sign_send_txn(raw_txn)

    def store(self, data):
        # Data is stored in OP_RETURNs within a series of chained transactions.
        # If the OP_RETURN is followed by another output, the data continues
        # in the transaction spending that output.
        # When the OP_RETURN is the last output, this also signifies the end
        # of the data.

        # Validate parameters and get change address
        err = self.bitcoin_check()
        if err:
            return error_(err)

        if isinstance(data, basestring):
            data = data.encode('utf-8') # convert to binary string

        data_len = len(data)
        if not data_len:
            return error_('Some data is required to be stored')

        change_address = self.bitcoin_cmd('getrawchangeaddress')

        # Calculate amounts and choose first inputs to use
        # number of transactions required
        output_amount = self.txfee * int((data_len + self.maxBytes -1) /
                                         self.maxBytes)

        inputs_spend = self.select_inputs(output_amount)
        err = inputs_spend.get('error', None)
        if err:
            return error_(err)

        inputs = inputs_spend['inputs']
        input_amount = inputs_spend['total']

        # Find the current blockchain height and mempool txids
        height = int(self.bitcoin_cmd('getblockcount'))
        avoid_txids = self.bitcoin_cmd('getrawmempool')

        # Loop to build and send transactions
        result = {
            'txids': []
        }

        for data_ptr in range(0, data_len, self.maxBytes):
            # Some preparation for this iteration
            # is this the last tx in the chain?
            last_txn = ((data_ptr + self.maxBytes) >= data_len)
            change_amount = input_amount - self.txfee
            metadata = data[data_ptr:data_ptr + self.maxBytes]

            # Build and send this transaction
            outputs = {}

            # might be skipped for last transaction
            if change_amount >= self.dust:
                outputs[change_address] = change_amount

            raw_txn = self.create_txn(inputs, outputs, metadata,
                                      len(outputs) if last_txn else 0)

            send_result = self.sign_send_txn(raw_txn)

            # Check for errors and collect the txid
            err = send_result.get('error', None)
            if err:
                result['error'] = err
                break

            result['txids'].append(send_result['txid'])

            if data_ptr == 0:
                result['ref'] = calc_ref(height, send_result['txid'],
                                         avoid_txids)

            # Prepare inputs for next iteration
            inputs = [{
                'txid': send_result['txid'],
                'vout': 1,
            }]

            input_amount = change_amount

        # Return the final result
        return result

    def retrieve(self, ref, max_results=1):
        # Validate parameters and get status of Bitcoin Core
        err = self.bitcoin_check()
        if err:
            return error_(err)

        max_height = int(self.bitcoin_cmd('getblockcount'))
        heights = get_ref_heights(ref, max_height)

        if not isinstance(heights, list):
            return error_('Ref is not valid')

        # Collect and return the results
        results = []

        for height in heights:
            if height == 0:
                # if mempool, only get list for now (to save RPC calls)
                txids = self.list_mempool_txns()
                txns=None
            else:
                # if block, get all fully unpacked
                txns = self.get_block_txns(height)
                txids = txns.keys()

            for txid in txids:
                if match_ref_txid(ref, txid):
                    if height == 0:
                        txn_unpacked = self.get_mempool_txn(txid)
                    else:
                        txn_unpacked = txns[txid]

                    found = find_txn_data(txn_unpacked)

                    if found:
                        # Collect data from txid which matches ref and
                        # contains an OP_RETURN

                        result = {
                            'txids': [str(txid)],
                            'data': found['op_return'],
                        }

                        key_heights = {
                            height: True
                        }

                        # Work out which other block heights / mempool we
                        # should try

                        if height == 0:
                            # nowhere else to look if first still in mempool
                            try_heights = []
                        else:
                            result['ref'] = calc_ref(height, txid, txns.keys())
                            try_heights = get_try_heights(height + 1,
                                    max_height, False)

                        # Collect the rest of the data, if appropriate
                        if height == 0:
                            # now retrieve all to follow chain
                            this_txns = self.get_mempool_txns()
                        else:
                            this_txns = txns

                        last_txid = txid
                        this_height = height

                        # this means more data to come
                        while found['index'] < (len(txn_unpacked['vout']) - 1):
                            next_txid = find_spent_txid(this_txns, last_txid,
                                                        found['index'] + 1)

                            # If we found the next txid in the data chain
                            if next_txid:
                                result['txids'].append(str(next_txid))

                                txn_unpacked = this_txns[next_txid]
                                found = find_txn_data(txn_unpacked)

                                if found:
                                    result['data'] += found['op_return']
                                    key_heights[this_height] = True
                                else:
                                    result['error'] = 'Data incomplete - missing OP_RETURN'
                                    break

                                last_txid = next_txid

                            # Otherwise move on to next height to keep looking
                            elif len(try_heights):
                                this_height = try_heights.pop(0)

                                if this_height == 0:
                                    this_txns = self.get_mempool_txns()
                                else:
                                    this_txns = self.get_block_txns(this_height)
                            else:
                                result['error'] = 'Data incomplete - could not find next transaction'
                                break

                        # Finish up the information about this result
                        result['heights'] = list(key_heights.keys())
                        results.append(result)

            if len(results) >= max_results:
                break # stop if we have collected enough

        return results

    def select_inputs(self, total_amount, send_address=None, max_amount=None):
        # List and sort unspent inputs by priority
        unspent_inputs = self.bitcoin_cmd('listunspent', 0)
        if not isinstance(unspent_inputs, list):
            return error_('Could not retrieve list of unspent inputs')

        if send_address:
            unspent_inputs = [x for x in unspent_inputs
                              if x['address'] != send_address]
        if max_amount:
            unspent_inputs = [x for x in unspend_inputs
                              if x['amount'] <= max_amount]

        unspent_inputs.sort(key=lambda x: x['amount'] * x['confirmations'],
                            reverse=True)

        # Identify which inputs should be spent
        inputs_spend = []
        input_amount = 0

        for unspent_input in unspent_inputs:
            inputs_spend.append(unspent_input)

            input_amount += unspent_input['amount']
            if input_amount >= total_amount:
                break # stop when we have enough

        if input_amount < total_amount:
            return error_('Not enough funds are available to cover the amount and fee')

        # Return the successful result
        return {
            'inputs': inputs_spend,
            'total': input_amount,
            'count': len(inputs_spend)
        }

    def select_all_inputs(self, send_address=None, max_count=None,
                          max_amount=None):
        # List and sort unspent inputs by priority
        unspent_inputs = self.bitcoin_cmd('listunspent', 0)
        if not isinstance(unspent_inputs, list):
            return error_('Could not retrieve list of unspent inputs')

        logger.info("Raw input count: %s" % len(unspent_inputs))

        if send_address:
            unspent_inputs = [x for x in unspent_inputs
                              if x.get('address', None) != send_address and
                                 x['confirmations'] >= self.min_confirmations and
                                 x['confirmations'] <= self.max_confirmations]

        logger.info("After address/confirmation filter: %s" % len(unspent_inputs))

        if max_amount:
            unspent_inputs = [x for x in unspent_inputs
                              if x['amount'] <= max_amount]

        logger.info("After amount filter: %s" % len(unspent_inputs))

        unspent_inputs.sort(key=lambda x: x['amount'] * x['confirmations'],
                            reverse=True)

        # Identify which inputs should be spent
        inputs_spend = []
        input_amount = 0
        input_count = 0

        for unspent_input in unspent_inputs:
            inputs_spend.append(unspent_input)

            input_amount += unspent_input['amount']
            input_count += 1
            if max_count and input_count >= max_count:
                break

        # Return the successful result
        return {
            'inputs': inputs_spend,
            'total': input_amount,
            'count': input_count,
        }

    def create_txn(self, inputs, outputs, metadata, metadata_pos):
        raw_txn = self.bitcoin_cmd('createrawtransaction', inputs, outputs)

        txn = Transaction(self.digits, self.use_message, binary=raw_txn)
        txn_unpacked = txn.txn

        metadata_len = len(metadata)

        scriptPubKey = BitcoinBuffer()
        # Here's the OP_RETURN
        scriptPubKey.pack_uint8(0x6A)

        if metadata_len <= 75:
            # length byte + data (https://en.bitcoin.it/wiki/Script)
            scriptPubKey.pack_uint8(metadata_len)
        elif metadata_len <= 256:
            # OP_PUSHDATA1 format
            scriptPubKey.pack_uint8(0x4C)
            scriptPubKey.pack_uint8(metadata_len)
        else:
            # OP_PUSHDATA2 format
            scriptPubKey.pack_uint8(0x4D)
            scriptPubKey.pack_uint16(metadata_len)

        scriptPubKey.pack(metadata)

        # constrain to valid values
        metadata_pos = min(max(0, metadata_pos), len(txn_unpacked['vout']))

        # here's the OP_RETURN
        txn_unpacked['vout'][metadata_pos:metadata_pos]=[{
            'value': 0,
            'scriptPubKey': '6a' + bin_to_hex(payload)
        }]
        
        txn = Transaction(self.digits, self.use_message, txn=txn_unpacked)
        return bin_to_hex(txn.binary)

    def create_burn_txn(self, inputs, outputs, metadata):
        tx = {}
        tx['version'] = 1
        tx['time'] = int(time.time())
        tx['locktime'] = 0
        tx['vin'] = []
        tx['vout'] = []

        for input in inputs:
            vin = {
                'txid': input['txid'],
                'vout': input['vout'],
                'scriptSig': "",
                'sequence': 0xFFFFFFFF,
            }

            tx['vin'].append(vin)

        metadata_len = len(metadata)

        if metadata_len <= 75:
            # length byte + data (https://en.bitcoin.it/wiki/Script)
            payload = bytearray((metadata_len,)) + metadata 
        elif metadata_len <= 256:
            # OP_PUSHDATA1 format
            payload = b"\x4c" + bytearray((metadata_len,)) + metadata
        else:
            # OP_PUSHDATA2 format
            payload = b"\x4d" + bytearray((metadata_len % 256,)) + \
                      bytearray((int(metadata_len / 256),)) + metadata

        for (addr, value) in outputs.items():
            vout = {
                'value': value
            }

            if addr == 'burn':
                # here's the OP_RETURN
                vout['scriptPubKey'] = '6a' + bin_to_hex(payload)
            else:
                ripeaddr = bin_to_hex(base58.b58decode(addr))
                # Take off leading letter, trailing checksum
                pubkey = ripeaddr[2:-8]
                vout['scriptPubKey'] = '76a914' + pubkey + '88ac'

            tx['vout'].append(vout)

        txn = Transaction(self.digits, self.use_message, txn=tx)
        return bin_to_hex(txn.binary)

    def sign_send_txn(self, raw_txn):
        logger.debug("Raw transaction: %s" % raw_txn)
        logger.info("Length of raw transaction: %s" % len(raw_txn))

        signed_txn = self.bitcoin_cmd('signrawtransaction', raw_txn)
        complete = signed_txn.get('complete', False)
        if not complete:
            return error_('Could not sign the transaction')

        with open("rawtransaction.txt", "w") as f:
            f.write(signed_txn['hex'])

        logger.info("Length of signed transaction: %s" % len(signed_txn['hex']))
        return self.send_txn(signed_txn['hex'])

    def send_txn(self, signed_txn_hex):
        send_txid = self.bitcoin_cmd('sendrawtransaction', signed_txn_hex)
        if not (isinstance(send_txid, basestring) and len(send_txid) == 64):
            return error_('Could not send the transaction')

        return {'txid': str(send_txid)}

    def list_mempool_txns(self):
        return self.bitcoin_cmd('getrawmempool')

    def get_mempool_txn(self, txid):
        raw_txn = self.bitcoin_cmd('getrawtransaction', txid)
        txn = Transaction(self.digits, self.use_message, binary=raw_txn)
        return txn.txn

    def get_mempool_txns(self):
        txids = self.list_mempool_txns(testnet)

        txns = {txid: get_mempool_txn(txid) for txid in txids}
        return txns

    def get_raw_block(self, height):
        block_hash = self.bitcoin_cmd('getblockhash', height)
        if not (isinstance(block_hash, basestring) and len(block_hash) == 64):
            return error_('Block at height %s not found' % height)

        return {
            'block': hex_to_bin(self.bitcoin_cmd('getblock', block_hash, False))
        }

    def get_block_txns(self, height):
        raw_block = self.get_raw_block(height)
        err = raw_block.get('error', None)
        if err:
            return error_(err)

        block = Block(self.digits, self.use_message, raw_block['block'])
        return block.block['txs']


    def bitcoin_check(self):
        info = self.bitcoin_cmd('getinfo')

        if isinstance(info, dict) and 'balance' in info:
            return False

        return 'Please check Bitcoin Core is running and class constants are set correctly'

    def bitcoin_cmd(self, command, *args):
        request = {
            'id': "%s-%s" % (int(time.time()), random.randint(100000,999999)),
            'method': command,
            'params': args,
        }

        logger.info("Sending command: %s" % command)
        logger.debug("Sending request: %s" % request)

        try:
            raw_result = self.session.post(self.url, json=request)
            result_array = raw_result.json()
            result = result_array['result']
        except Exception as e:
            result = { "error": "ERROR: %s" % str(e) }

        logger.debug("Response to %s command: %s" % (command, result))
        return result


# Working with data references

# The format of a data reference is: [estimated block height]-[partial txid] - where:

# [estimated block height] is the block where the first transaction might appear and following
# which all subsequent transactions are expected to appear. In the event of a weird blockchain
# reorg, it is possible the first transaction might appear in a slightly earlier block. When
# embedding data, we set [estimated block height] to 1+(the current block height).

# [partial txid] contains 2 adjacent bytes from the txid, at a specific position in the txid:
# 2*([partial txid] div 65536) gives the offset of the 2 adjacent bytes, between 0 and 28.
# ([partial txid] mod 256) is the byte of the txid at that offset.
# (([partial txid] mod 65536) div 256) is the byte of the txid at that offset plus one.
# Note that the txid is ordered according to user presentation, not raw data in the block.


def calc_ref(next_height, txid, avoid_txids):
    txid_binary = hex_to_bin(txid)

    for txid_offset in range(15):
        start_offset = 2 * txid_offset
        sub_txid = txid_binary[start_offset:start_offset + 2]
        clashed = False

        for avoid_txid in avoid_txids:
            avoid_txid_binary = hex_to_bin(avoid_txid)

            if avoid_txid_binary[start_offset:start_offset + 2] == sub_txid \
                    and txid_binary != avoid_txid_binary:
                clashed=True
                break

        if not clashed:
            break

    if clashed: # could not find a good reference
        return None

    buffer = BitcoinBuffer(txid_binary, start_offset)
    tx_ref = buffer.unpack_16() + (txid_offset << 16)

    return '%06d-%06d' % (next_height, tx_ref)


def get_ref_parts(ref):
    # also support partial txid for second half
    if not re.search('^[0-9]+\-[0-9A-Fa-f]+$', ref):
        return None

    parts = ref.split('-')

    if re.search('[A-Fa-f]', parts[1]):
        if len(parts[1]) < 4:
            return None

        txid_binary = hex_to_bin(parts[1][0:4])
        buffer = BitcoinBuffer(txid_binary)
        parts[1] = buffer.unpack_uint16()

    parts = list(map(int, parts))

    if parts[1] > 0x0EFFFF: # 14*65536+65535
        return None

    return parts


def get_ref_heights(ref, max_height):
    parts = get_ref_parts(ref)
    if not parts:
        return None

    return get_try_heights(parts[0], max_height, True)


def get_try_heights(est_height, max_height, also_back):
    forward_height = est_height
    back_height = min(forward_height - 1, max_height)

    heights = []
    mempool = False
    try_height = 0

    while True:
        if also_back and ((try_height % 3)==2): # step back every 3 tries
            heights.append(back_height)
            back_height -= 1

        else:
            if forward_height > max_height:
                if not mempool:
                    # indicates to try mempool
                    heights.append(0)
                    mempool = True
                elif not also_back:
                    break # nothing more to do here
            else:
                heights.append(forward_height)

            forward_height += 1

        if len(heights) >= self.maxBlocks:
            break

        try_height += 1

    return heights


def match_ref_txid(ref, txid):
    parts = get_ref_parts(ref)
    if not parts:
        return None

    txid_offset = int(parts[1] >> 16) * 2
    txid_binary = hex_to_bin(txid)

    txid_part = txid_binary[txid_offset:txid_offset + 2]

    buffer = BitcoinBuffer()
    buffer.pack_uint16(parts[1])
    txid_match = buffer.data

    # exact binary comparison
    return txid_part == txid_match


# Unpacking and packing bitcoin blocks and transactions

class Block:
    def __init__(self, digits, use_message, binary):
        self.digits = digits
        self.use_message = use_message
        self.binary = binary
        self.block = self.unpack_block()

    def unpack_block(self):
        buffer = BitcoinBuffer(self.binary)
        block = {
            'version': buffer.unpack_uint32(),
            'hashPrevBlock': bin_to_hex(buffer.unpack(32)[::-1]),
            'hashMerkleRoot': bin_to_hex(buffer.unpack(32)[::-1]),
            'time': buffer.unpack_uint32(),
            'bits': buffer.unpack_uint32(),
            'nonce': buffer.unpack_uint32(),
            'tx_count': buffer.unpack_varint(),
            'txs': {},
        }

        old_ptr = buffer.used()

        while buffer.remaining():
            transaction = Transaction(self.digits, self.use_message,
                                      buffer=buffer)
            transaction = transaction.txn
            new_ptr = buffer.used()
            size = new_ptr - old_ptr

            sha = hashlib.sha256(binary[old_ptr:new_ptr]).digest()
            sha2 = hashlib.sha256(sha).digest()
            txid = bin_to_hex(sha2[::-1])

            old_ptr = new_ptr

            transaction['size'] = size
            block['txs'][txid] = transaction

        return block


def find_spent_txid(txns, spent_txid, spent_vout):
    for txid, txn_unpacked in txns.items():
        for input in txn_unpacked['vin']:
            if (input['txid'] == spent_txid) and (input['vout'] == spent_vout):
                return txid

    return None


def find_txn_data(txn_unpacked):
    for index, output in enumerate(txn_unpacked['vout']):
        op_return = get_script_data(hex_to_bin(output['scriptPubKey']))

        if op_return:
            return {
                'index': index,
                'op_return': op_return,
            }

    return None


def get_script_data(scriptPubKeyBinary):
    op_return = None

    buffer = BitcoinBuffer(scriptPubKeyBinary)
    opcode = buffer.unpack_uint8()
    if opcode != 0x6A:
        return None

    length = buffer.unpack_uint8()
    if length == 0x4C:
        length = buffer.unpack_uint8()
    elif length == 0x4D:
        length = buffer.unpack_uint16()
    elif length > 75:
        # Invalid / not supported
        return None

    op_return = buffer.unpack(length)
    return op_return


class Transaction:
    def __init__(self, digits, use_message, txn=None, binary=None, buffer=None):
        self.digits = digits
        self.scaler = 10 ** digits
        self.use_message = use_message

        if binary and not buffer:
            buffer = BitcoinBuffer(binary)

        self.binary = binary
        self.txn = txn
        self.buffer = buffer


        if txn and not buffer:
            self.binary = self.pack_txn()
        elif buffer and not txn:
            self.txn = self.unpack_txn()
        else:
            raise Exception("Invalid parameters, must be one of txn, binary, buffer")

    def pack_txn(self):
        txn = self.txn
        buffer = BitcoinBuffer()

        buffer.pack_uint32(txn['version'])
        buffer.pack_uint32(txn['time'])

        buffer.pack_varint(len(txn['vin']))

        for input in txn['vin']:
            buffer.pack(hex_to_bin(input['txid'])[::-1])
            buffer.pack_uint32(input['vout'])
            # divide by 2 because it is currently in hex
            buffer.pack_varint(len(input['scriptSig']) / 2)
            buffer.pack(hex_to_bin(input['scriptSig']))
            buffer.pack_uint32(input['sequence'])

        buffer.pack_varint(len(txn['vout']))

        for output in txn['vout']:
            buffer.pack_uint64(round(output['value'] * self.scaler))
            # divide by 2 because it is currently in hex
            buffer.pack_varint(len(output['scriptPubKey']) / 2)
            buffer.pack(hex_to_bin(output['scriptPubKey']))

        buffer.pack_uint32(txn['locktime'])
        if self.use_message:
            buffer.pack(hex_to_bin(b"046275726e"))

        return buffer.data

    def unpack_txn(self):
        buffer = self.buffer

        # see: https://en.bitcoin.it/wiki/Transactions
        txn = {
            'vin': [],
            'vout': [],
        }

        txn['version'] = buffer.unpack_uint32() # small-endian 32-bits
        txn['time'] = buffer.unpack_uint32()    # small-endian 32-bits

        inputs = buffer.unpack_varint()
        if inputs > 100000: # sanity check
            return None

        for _ in range(inputs):
            input={}

            input['txid'] = bin_to_hex(buffer.unpack(32)[::-1])
            input['vout'] = buffer.unpack_uint32()
            length = buffer.unpack_varint()
            input['scriptSig'] = bin_to_hex(buffer.unpack(length))
            input['sequence'] = buffer.unpack_uint32()

            txn['vin'].append(input)

        outputs = buffer.unpack_varint()
        if outputs > 100000: # sanity check
            return None

        for _ in range(outputs):
            output={}

            output['value'] = float(buffer.unpack_uint64()) / self.scaler
            length = buffer.unpack_varint()
            output['scriptPubKey'] = bin_to_hex(buffer.unpack(length))

            txn['vout'].append(output)

        txn['locktime'] = buffer.unpack_uint32()
        return txn


# Helper class for unpacking bitcoin binary data

class BitcoinBuffer():

    def __init__(self, data=None, ptr=0):
        if data is None:
            data = b''
        self.data = data
        self.len = len(data)
        self.ptr = ptr

    def unpack(self, chars):
        prefix = self.data[self.ptr:self.ptr + chars]
        self.ptr += chars
        return prefix

    def unpack_format(self, chars, format):
        unpack = struct.unpack(format, self.unpack(chars))
        return unpack[0]

    def unpack_varint(self):
        value = self.unpack_uint8()

        if value == 0xFF:
            value = self.unpack_uint64()
        elif value == 0xFE:
            value = self.unpack_uint32()
        elif value == 0xFD:
            value = self.unpack_uint16()

        return value

    def unpack_uint64(self):
        return self.unpack_uint32() + (self.unpack_uint32() << 32)

    def unpack_uint32(self):
        return self.unpack_format(4, '<L')

    def unpack_uint16(self):
        return self.unpack_format(2, '<H')

    def unpack_uint8(self):
        return self.unpack_format(1, 'B')

    def pack(self, data):
        self.data += data
        self.len += len

    def pack_varint(self, number):
        number = int(number)

        if number > 0xFFFFFFFF:
            self.pack_uint8(0xFF)
            self.pack_uint64(number)
        elif integer > 0xFFFF:
            self.pack_uint8(0xFE)
            self.pack_uint32(number)
        elif integer > 0xFC:
            self.pack_uint8(0xFD)
            self.pack_uint16(number)
        else:
            self.pack_uint8(number)
        
    def pack_uint64(self, number):
        number = int(number)
        self.pack_uint32(number & 0xFFFFFFFF)   # lower
        self.pack_uint32(number >> 32)          # upper

    def pack_uint32(self, number):
        number = int(number) & 0xFFFFFFFF
        self.data += struct.pack('<L', number)
        self.len += 4

    def pack_uint16(self, number):
        number = int(number) & 0xFFFF
        self.data += struct.pack('<H', number)
        self.len += 2

    def pack_uint8(self, number):
        number = int(number) & 0xFF
        self.data += struct.pack('B', number)
        self.len += 1

    def used(self):
        return min(self.ptr, self.len)

    def remaining(self):
        return max(self.len - self.ptr, 0)


def hex_to_bin(hex):
    try:
       return binascii.a2b_hex(hex)
    except Exception:
        return None


def bin_to_hex(string):
    return binascii.b2a_hex(string).decode('utf-8')


def error_(message):
    return {'error': message}

# vim:ts=4:sw=4:ai:et:si:sts=4
