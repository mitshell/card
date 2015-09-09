# -*- coding: UTF-8 -*-
"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2010 Benoit Michau

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

#################################
# generic functions             #
# being used in smartcard specs #
#################################

from collections import deque
from smartcard.util import toBytes


###############
# log wrapper #
###############
log_levels = {1:'ERR', 2:'WNG', 3:'DBG'}
def log(level, string):
    # could output to a file
    # but here, just print()
    print('[%s] %s' % (log_levels[level], string))
    
# from python 2.6, format('b') allows to use 0b10010110 notation: 
# much convinient
def byteToBit(byte):
    '''
    byteToBit(0xAB) -> [1, 0, 1, 0, 1, 0, 1, 1]
    
    converts a byte integer value into a list of bits
    '''
    bit = [0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(8):
        if byte % pow(2, i+1):
            bit[7-i] = 1
            byte = byte - pow(2, i)
    return bit

# equivalent to the pyscard function "toASCIIBytes"
# new version of python (>2.6) seems to have a built-in "bytes" type
def stringToByte(string):
    '''
    stringToByte('test') -> [116, 101, 115, 116]
    
    converts a string into a list of bytes
    '''
    bytelist = []
    for c in string:
        bytelist.extend( toBytes(c.encode('hex')) )
    return bytelist

# equivalent to the pyscard function "toASCIIString"
def byteToString(bytelist):
    '''
    byteToString([116, 101, 115, 116]) -> 'test'
    
    converts a list of bytes into a string
    '''
    string = ''
    for b in bytelist:
        string += chr(b)
    return string

def LV_parser(bytelist):
    '''
    LV_parser([0x02, 0xAB, 0xCD, 0x01, 0x12, 0x34]) -> [[171, 205], [18], []]
    
    parses Length-Value records in a list of bytes
    returns a list of list of bytes
    length coded on 1 byte
    '''
    values = []
    while len(bytelist) > 0:
        l = bytelist[0]
        values.append( bytelist[1:1+l] )
        bytelist = bytelist[1+l:]
    return values

def first_TLV_parser(bytelist):
    '''
    first_TLV_parser([0xAA, 0x02, 0xAB, 0xCD, 0xFF, 0x00]) -> (170, 2, [171, 205])
    
    parses first TLV format record in a list of bytelist 
    returns a 3-Tuple: Tag, Length, Value
    Value is a list of bytes
    parsing of length is ETSI'style 101.220
    '''
    Tag = bytelist[0]
    if bytelist[1] == 0xFF:
        Len = bytelist[2]*256 + bytelist[3]
        Val = bytelist[4:4+Len]
    else:
        Len = bytelist[1]
        Val = bytelist[2:2+Len]
    return (Tag, Len, Val)

def TLV_parser(bytelist):
    '''
    TLV_parser([0xAA, ..., 0xFF]) -> [(T, L, [V]), (T, L, [V]), ...]
    
    loops on the input list of bytes with the "first_TLV_parser()" function
    returns a list of 3-Tuples
    '''
    ret = []
    while len(bytelist) > 0:
        T, L, V = first_TLV_parser(bytelist)
        if T == 0xFF:
            # padding bytes
            break
        ret.append( (T, L, V) )
        # need to manage length of L
        if L > 0xFE: 
            bytelist = bytelist[ L+4 : ]
        else: 
            bytelist = bytelist[ L+2 : ]
    return ret

def first_BERTLV_parser(bytelist):
    '''
    first_BERTLV_parser([0xAA, 0x02, 0xAB, 0xCD, 0xFF, 0x00]) 
        -> ([1, 'contextual', 'constructed', 10], [1, 2], [171, 205])
    
    parses first BER-TLV format record in a list of bytes
    returns a 3-Tuple: Tag, Length, Value
        Tag: [Tag class, Tag DO, Tag number]
        Length: [Length of length, Length value]
        Value: [Value bytes list]
    parsing of length is ETSI'style 101.220
    '''
    # Tag class and DO
    byte0 = byteToBit(bytelist[0])
    if byte0[0:2] == [0, 0]:
        Tag_class = 'universal'
    elif byte0[0:2] == [0, 1]:
        Tag_class = 'applicative'
    elif byte0[0:2] == [1, 0]:
        Tag_class = 'contextual'
    elif byte0[0:2] == [1, 1]:
        Tag_class = 'private'
    if byte0[2:3] == [0]:
        Tag_DO = 'primitive'
    elif byte0[2:3] == [1]:
        Tag_DO = 'constructed'
    # Tag coded with more than 1 byte
    i = 0
    if byte0[3:8] == [1, 1, 1, 1, 1]:
        Tag_bits = byteToBit(bytelist[1])[1:8]
        i += 1
        while byteToBit(bytelist[i])[0] == 1:
            i += 1
            Tag_bits += byteToBit(bytelist[i])[1:8]
    # Tag coded with 1 byte
    else:
        Tag_bits = byte0[3:8]
    
    # Tag number calculation 
    Tag_num = 0
    for j in range(len(Tag_bits)):
        Tag_num += Tag_bits[len(Tag_bits)-j-1] * pow(2, j)
    
    # Length coded with more than 1 byte (BER long form)
    if bytelist[i+1] & 0x80:
        Len_num = bytelist[i+1] - 0x80
        Len = reduce(lambda x,y: (x<<8)+y, bytelist[i+2:i+2+Len_num])
        Val = bytelist[i+2+Len_num:i+2+Len_num+Len]
    # Length coded with 1 byte
    else:
        Len_num = 1
        Len = bytelist[i+1]
        Val = bytelist[i+2:i+2+Len]

    return ([i+1, Tag_class, Tag_DO, Tag_num], [Len_num, Len], Val)
    #return ([Tag_class, Tag_DO, Tag_num], Len, Val)

def BERTLV_parser(bytelist):
    '''
    BERTLV_parser([0xAA, ..., 0xFF]) -> [([T], L, [V]), ([T], L, [V]), ...]
    
    loops on the input bytes with the "first_BERTLV_parser()" function
    returns a list of 3-Tuples containing BERTLV records
    '''
    ret = []
    while len(bytelist) > 0:
        T, L, V = first_BERTLV_parser(bytelist)
        #if T == 0xFF: 
        #    break # padding bytes
        ret.append( (T[1:], L[1], V) )
        # need to manage lengths of Tag and Length
        bytelist = bytelist[ T[0] + L[0] + L[1] : ]
    return ret

def decode_BCD(data=[]):
    '''
    decode_BCD([0x21, 0xFE, 0xA3]) -> '121415310'
    
    to decode serial number (IMSI, ICCID...) from list of bytes
    '''
    string = ''
    for B in data:
        # 1st digit (4 LSB), can be padding (e.g. 0xF)
        if (B&0x0F) < 10: string += str(B&0x0F)
        # 2nd digit (4 MSB), can be padding (e.g. 0xF)
        if (B>>4) < 10: string += str(B>>4)
    return string

def compute_luhn(digit_str=''):
    '''
    compute_luhn('15632458') -> 4
    
    return the luhn code of the digits provided
    '''
    if not digit_str.isdigit():
        print('you must provide a string of digits')
        return
    # append 0
    d = [int(c) for c in digit_str+'0']
    # sum of odd digits
    cs = sum(d[-1::-2])
    # sum of (sum of digits(even digits * 2))
    cs += sum([(v*2)%9 if v != 9 else 9 for v in d[-2::-2]])
    # modulo 10: luhn checksum
    cs = cs%10
    # return the luhn code
    if cs == 0: return cs
    else: return 10-cs
    
def write_dict(dict, fd):
    '''
    write a dict() content to a file descriptor
    '''
    keys = dict.keys()
    keys.sort()
    fd.write('\n')
    for k in keys:
        rec = dict[k]
        if isinstance(rec, list) and \
        len(rec) == [isinstance(i, int) for i in rec].count(True):
            rec = ''.join(['[', ', '.join(map(hex, rec)), ']'])
        fd.write('%s: %s\n' % (k, rec))

def make_graph(FS, master_name='(0x3F, 0x00)\nMF'):
    try:
        import pydot
    except:
        log(1, '(make_graph) pydot library not found: aborting')
        return
    #return
    # build a graph using graphviz Dot language, with pydot
    # create a graph with master MF or AID node
    nodes={}
    graph = pydot.Dot(graph_type='digraph', rankdir='LR')
    nodes['master'] = pydot.Node(master_name, style='filled', fillcolor='green')
    graph.add_node(nodes['master'])
    # attach nodes under master
    for file in FS:
        abspath = file['Absolut Path']
        # build file name for the node
        label = ''.join(( \
            ''.join((file['Name'], '\n')) if 'Name' in file.keys() else '', \
            '(', hex(abspath[-2]), ' ', hex(abspath[-1]), ')'))
        # check for EF or DF for node color
        color='yellow' if file['Type'][:2] == 'EF' else 'blue'
        # make node
        nodes['%s'%abspath] = pydot.Node('%s'%abspath, label=label,\
                              style='filled', fillcolor=color)
        # put it in the graph and append it to the parent
        graph.add_node(nodes['%s'%abspath])
        graph.add_edge(pydot.Edge(nodes['%s'%abspath[:-2]] if \
                        len(abspath) >= 4 else nodes['master'], \
                        nodes['%s'%abspath]))
    # and return graph ...
    return graph
    
    

#######################################################
# Generic class to keep track of sent / received APDU #
#######################################################
class apdu_stack:
    '''
    input / output wrapping class
    for APDU communications
    
    allows to keep track of communications
    and exchanged commands
    
    based on the python "deque" fifo-like object
    '''

    def __init__(self, limit=10):
        '''
        initializes apdu_stack with the maximum of IO to keep track of
        '''
        self.apdu_stack  = deque([], limit)
        
    def push(self, apdu_response):
        '''
        stacks the returned response into the apdu_stack
        '''
        self.apdu_stack.append( apdu_response )
    
    def __repr__(self):
        '''
        represents the whole stack of responses pushed on
        '''
        s = ''
        for apdu in self.apdu_stack:
            s += apdu.__repr__() + '\n'
        return s
    
    def __call__(self):
        '''
        calling the apdu_stack returns the last response pushed on it
        '''
        try:
            return self.apdu_stack[-1]
        except IndexError:
            return None

