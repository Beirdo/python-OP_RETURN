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

# Python 2-3 compatibility logic

try:
    basestring
except NameError:
    basestring = str


class OpReturn:
    ip = '127.0.0.1' # IP address of your bitcoin node
    txfee = 0.0001   # Transaction fee
    dust = 0.00001   # omit outputs smaller than this
    maxBytes = 80    # maximum bytes in an OP_RETURN (80 as of Bitcoin 0.11)
    maxBlocks = 10   # maximum number of blocks to try when retrieving data
    timeout = 10     # timeout (in s) when communicating with node

    def __init__(self, coin_name, testnet=False):
        self.testnet = testnet
        self.coin_name = coin_name
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
        self.session = requests.session
        self.session.auth = (self.user, self.password)
        self.session.timeout = self.timeout

    def burn(self, burn_amount, metadata):
        # Validate some parameters
        err = self.bitcoin_check():
        if err:
            return error_(err)

        if isinstance(metadata, basestring):
            metadata = metadata.encode('utf-8') # convert to binary string

        metadata_len = len(metadata)

        if metadata_len > self.maxBytes:
            return error_('Metadata has %s bytes but is limited to %s (see self.maxBytes)' % (metadata_len, self.maxBytes))

        if metadata_len > 65536:
            return error_('This library only supports metadata up to 65536 bytes in size')

        # Calculate amounts and choose inputs
        output_amount = burn_amount + self.txfee

        inputs_spend = self.select_inputs(output_amount)

        err = inputs_send.get('error', None)
        if err:
            return error_(err)

        change_amount = inputs_spend['total'] - output_amount

        # Build the raw transaction
        outputs = {
            "burn": send_amount
        }

        if change_amount >= self.dust:
            change_address = self.bitcoin_cmd('getaccountaddress', 'change')
            outputs[change_address] = change_amount

        raw_txn = self.create_burn_txn(inputs_spend['inputs'], outputs,
                                       metadata)

        # Sign and send the transaction, return result
        return self.sign_send_txn(raw_txn)

    def send(self, send_address, send_amount, metadata):
        # Validate some parameters
        err = self.bitcoin_check():
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

        if metadata_len > 65536:
            return error_('This library only supports metadata up to 65536 bytes in size')

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
        err = self.bitcoin_check():
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
        err = self.bitcoin_check():
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

    def select_inputs(self, total_amount):
        # List and sort unspent inputs by priority
        unspent_inputs = self.bitcoin_cmd('listunspent', 0)
        if not isinstance(unspent_inputs, list):
            return error_('Could not retrieve list of unspent inputs')

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
        }

    def create_txn(self, inputs, outputs, metadata, metadata_pos):
        raw_txn = self.bitcoin_cmd('createrawtransaction', inputs, outputs)

        txn_unpacked = unpack_txn(hex_to_bin(raw_txn))

        metadata_len=len(metadata)

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

        # constrain to valid values
        metadata_pos = min(max(0, metadata_pos), len(txn_unpacked['vout']))

        # here's the OP_RETURN
        txn_unpacked['vout'][metadata_pos:metadata_pos]=[{
            'value': 0,
            'scriptPubKey': '6a' + bin_to_hex(payload)
        }]
        
        return bin_to_hex(pack_txn(txn_unpacked))

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

        return bin_to_hex(pack_txn(tx))

    def sign_send_txn(self, raw_txn):
        signed_txn = self.bitcoin_cmd('signrawtransaction', raw_txn)
        complete = signed_txn.get('complete', False)
        if not complete:
            return error_('Could not sign the transaction')

        send_txid = self.bitcoin_cmd('sendrawtransaction', signed_txn['hex'])
        if not (isinstance(send_txid, basestring) and len(send_txid) == 64):
            return error_('Could not send the transaction')

        return {'txid': str(send_txid)}

    def list_mempool_txns(self):
        return self.bitcoin_cmd('getrawmempool')

    def get_mempool_txn(self, txid):
        raw_txn = self.bitcoin_cmd('getrawtransaction', txid)
        return unpack_txn(hex_to_bin(raw_txn))

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

        block = unpack_block(raw_block['block'])

        return block['txs']


    def bitcoin_check(self):
        info = self.bitcoin_cmd('getinfo')

        if isinstance(info, dict) and 'balance' in info:
            return False

        return 'Please check Bitcoin Core is running and class constants are set correctly'

    def bitcoin_cmd(self, coin_name, command, *args):
        request={
            'id': "%s-%s" % (int(time.time()), random.randint(100000,999999)),
            'method': command,
            'params': args,
        }

        try:
            raw_result = self.session.post(self.url, json=request)
            result_array = raw_result.json()
            result = result_array['result']
        except Exception as e:
            result = { "error": "ERROR: %s" % str(e) }

        print(result)
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

    tx_ref = ord(txid_binary[start_offset:start_offset + 1]) + \
        256 * ord(txid_binary[start_offset + 1:start_offset + 2]) +
        65536 * txid_offset

    return '%06d-%06d' % (next_height, tx_ref)


def get_ref_parts(ref):
    # also support partial txid for second half
    if not re.search('^[0-9]+\-[0-9A-Fa-f]+$', ref):
        return None

    parts = ref.split('-')

    if re.search('[A-Fa-f]', parts[1]):
        if len(parts[1]) >= 4:
            txid_binary = hex_to_bin(parts[1][0:4])
            parts[1] = ord(txid_binary[0:1]) + 256 * ord(txid_binary[1:2]) + \
                       65536 * 0
        else:
            return None

    parts = list(map(int, parts))

    if parts[1] > 983039: # 14*65536+65535
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

    txid_offset = int(parts[1] / 65536)
    txid_binary = hex_to_bin(txid)

    txid_part = txid_binary[2 * txid_offset:2 * txid_offset + 2]
    txid_match = bytearray([parts[1] % 256, int((parts[1] % 65536) / 256)])

    # exact binary comparison
    return txid_part == txid_match


# Unpacking and packing bitcoin blocks and transactions

def unpack_block(binary):
    buffer = BitcoinBuffer(binary)
    block = {}

    block['version'] = buffer.shift_unpack(4, '<L')
    block['hashPrevBlock'] = bin_to_hex(buffer.shift(32)[::-1])
    block['hashMerkleRoot'] = bin_to_hex(buffer.shift(32)[::-1])
    block['time'] = buffer.shift_unpack(4, '<L')
    block['bits'] = buffer.shift_unpack(4, '<L')
    block['nonce'] = buffer.shift_unpack(4, '<L')
    block['tx_count'] = buffer.shift_varint()

    block['txs'] = {}

    old_ptr = buffer.used()

    while buffer.remaining():
        transaction = unpack_txn_buffer(buffer)
        new_ptr = buffer.used()
        size = new_ptr - old_ptr

        raw_txn_binary = binary[old_ptr:old_ptr + size]
        txid = bin_to_hex(hashlib.sha256(hashlib.sha256(raw_txn_binary).digest()).digest()[::-1])

        old_ptr = new_ptr

        transaction['size'] = size
        block['txs'][txid] = transaction

    return block


def unpack_txn(binary):
    return unpack_txn_buffer(BitcoinBuffer(binary))


def unpack_txn_buffer(buffer):
    # see: https://en.bitcoin.it/wiki/Transactions
    txn = {
        'vin': [],
        'vout': [],
    }

    txn['version'] = buffer.shift_unpack(4, '<L') # small-endian 32-bits
    txn['time'] = buffer.shift_unpack(4, '<L') # small-endian 32-bits

    inputs = buffer.shift_varint()
    if inputs > 100000: # sanity check
        return None

    for _ in range(inputs):
        input={}

        input['txid'] = bin_to_hex(buffer.shift(32)[::-1])
        input['vout'] = buffer.shift_unpack(4, '<L')
        length = buffer.shift_varint()
        input['scriptSig'] = bin_to_hex(buffer.shift(length))
        input['sequence'] = buffer.shift_unpack(4, '<L')

        txn['vin'].append(input)

    outputs = buffer.shift_varint()
    if outputs > 100000: # sanity check
        return None

    for _ in range(outputs):
        output={}

        output['value'] = float(buffer.shift_uint64()) / 1000000.0
        length = buffer.shift_varint()
        output['scriptPubKey'] = bin_to_hex(buffer.shift(length))

        txn['vout'].append(output)

    txn['locktime'] = buffer.shift_unpack(4, '<L')
    return txn


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

    if scriptPubKeyBinary[0:1] == b'\x6a':
        first_ord = ord(scriptPubKeyBinary[1:2])

        if first_ord <= 75:
            op_return = scriptPubKeyBinary[2:2 + first_ord]
        elif first_ord == 0x4c:
            op_return = scriptPubKeyBinary[3:3 + ord(scriptPubKeyBinary[2:3])]
        elif first_ord == 0x4d:
            op_return = scriptPubKeyBinary[4:4 + ord(scriptPubKeyBinary[2:3]) \
                    + 256 * ord(scriptPubKeyBinary[3:4])]

    return op_return


def pack_txn(txn):
    binary = b''

    binary += struct.pack('<L', txn['version'])
    binary += struct.pack('<L', txn['time'])

    binary += pack_varint(len(txn['vin']))

    for input in txn['vin']:
        binary += hex_to_bin(input['txid'])[::-1]
        binary += struct.pack('<L', input['vout'])
        # divide by 2 because it is currently in hex
        binary += pack_varint(int(len(input['scriptSig'])/2))
        binary += hex_to_bin(input['scriptSig'])
        binary += struct.pack('<L', input['sequence'])

    binary += pack_varint(len(txn['vout']))

    for output in txn['vout']:
        binary += pack_uint64(int(round(output['value']*1000000)))
        # divide by 2 because it is currently in hex
        binary += pack_varint(int(len(output['scriptPubKey'])/2))
        binary += hex_to_bin(output['scriptPubKey'])

    binary += struct.pack('<L', txn['locktime'])
    binary += hex_to_bin(b"046275726e")

    return binary


def pack_varint(integer):
    if integer > 0xFFFFFFFF:
        packed = b"\xFF" + pack_uint64(integer)
    elif integer > 0xFFFF:
        packed = b"\xFE" + struct.pack('<L', integer)
    elif integer > 0xFC:
        packed = b"\xFD" + struct.pack('<H', integer)
    else:
        packed = struct.pack('B', integer)

    return packed


def pack_uint64(integer):
    integer = int(integer)
    upper = integer >> 32
    lower = integer & 0xFFFFFFFF

    return struct.pack('<L', lower) + struct.pack('<L', upper)


# Helper class for unpacking bitcoin binary data

class BitcoinBuffer():

    def __init__(self, data, ptr=0):
        self.data = data
        self.len = len(data)
        self.ptr = ptr

    def shift(self, chars):
        prefix = self.data[self.ptr:self.ptr + chars]
        self.ptr += chars

        return prefix

    def shift_unpack(self, chars, format):
        unpack = struct.unpack(format, self.shift(chars))

        return unpack[0]

    def shift_varint(self):
        value = self.shift_unpack(1, 'B')

        if value == 0xFF:
            value = self.shift_uint64()
        elif value == 0xFE:
            value = self.shift_unpack(4, '<L')
        elif value == 0xFD:
            value = self.shift_unpack(2, '<H')

        return value

    def shift_uint64(self):
        return self.shift_unpack(4, '<L') + (self.shift_unpack(4, '<L') << 32)

    def used(self):
        return min(self.ptr, self.len)

    def remaining(self):
        return max(self.len-self.ptr, 0)


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
