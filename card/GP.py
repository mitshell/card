# -*- coding: UTF-8 -*-
"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2018 Benoit Michau

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
# Python library to work on
# USIM card
# communication based on ISO7816 card
# and commands and formats based on UICC card
#
# needs pyscard from:
# http://pyscard.sourceforge.net/
#################################

from card.ICC   import UICC, ISO7816
from card.utils import *

from binascii import hexlify
import pprint
pp = pprint.PrettyPrinter(indent=2)

# see GP specs from https://globalplatform.org/specs-library/
# and many info from https://sourceforge.net/p/globalplatform/wiki/GPShell/
# 
# e.g. (from the GPShell wiki)
# Secure Channel Keys
#    Most cards are using 404142434445464748494A4B4C4D4E4F
#    GemXpresso Pro cards are using 47454d5850524553534f53414d504c45
#
# Secure Channel Key Versions
#    Most cards are using 0
#    Nokia NFC 6131 is using 42


class GP(UICC):
    '''
    defines attributes, methods and facilities for GlobalPlatform card
    check GP specifications in GPC Card Specifications
    
    inherits (eventually overrides) methods and objects from UICC class
    use self.dbg = 1 or more to print live debugging information
    '''
    
    FSDesc = {
        (0x00, 0x42): ('Issuer Identification Number',
                       '_dec_iin'),
        (0x00, 0x45): ('Card Image Number',
                       '_dec_cin'),
        (0x00, 0x4F): ('ISD AID',
                       '_dec_generic'),
        (0x00, 0x66): ('Card Data',
                       '_dec_data'),
        (0x00, 0x67): ('Card Capability Information',
                       '_dec_generic'),
        (0x00, 0xC1): ('Sequence Counter of the default Key Version Number',
                       '_dec_seq_cnt'),
        (0x00, 0xC2): ('Confirmation Counter',
                       '_dec_conf_cnt'),
        (0x00, 0xC6): ('Free EEPROM Space',
                       '_dec_generic'),
        (0x00, 0xC7): ('Free Transient CoR RAM',
                       '_dec_generic'),
        (0x00, 0xCF): ('Key Diversification',
                       '_dec_generic'),
        (0x00, 0xD3): ('Current Security Level',
                       '_dec_generic'),
        (0x00, 0xE0): ('Key Information Template',
                       '_dec_generic'),
        (0x2F, 0x00): ('List of Applications',
                       '_dec_generic'),
        (0x5F, 0x50): ('Security Domain Manager URL',
                       '_dec_generic'),
        (0x9F, 0x66): ('CPLC Personalization Date',
                       '_dec_generic'),
        (0x9F, 0x67): ('CPLC Pre-personalization Date',
                       '_dec_generic'),
        (0x9F, 0x68): ('CPLC ICC Manufacturer Embedding Date',
                       '_dec_generic'),
        (0x9F, 0x69): ('CPLC Module Fabricator Packaging Date',
                       '_dec_generic'),
        (0x9F, 0x6A): ('CPLC Fabrication Date, Serial and Batch ID',
                       '_dec_generic'),
        (0x9F, 0x7F): ('CPLC Complete',
                       '_dec_cplc'),
        (0xBF, 0x0C): ('FCI Data',
                       '_dec_generic'),
        (0xDF, 0x70): ('Data Protocol',
                       '_dec_generic'),
        (0xDF, 0x71): ('Data ATR Historical Bytes',
                       '_dec_generic'),
        (0xDF, 0x76): ('EF_prod Data Initialization Fingerprint',
                       '_dec_generic'),
        (0xDF, 0x77): ('EF_prod Data Initialization Data',
                       '_dec_generic'),
        (0xDF, 0x78): ('EF_prod Data Production Key Index',
                       '_dec_generic'),
        (0xDF, 0x79): ('EF_prod Data Protocol Version',
                       '_dec_generic'),
        (0xDF, 0x7A): ('EF_prod Data Checksum',
                       '_dec_generic'),
        (0xDF, 0x7B): ('EF_prod Data Software Version',
                       '_dec_generic'),
        (0xDF, 0x7C): ('EF_prod Data RFU',
                       '_dec_generic'),
        (0xDF, 0x7D): ('EF_prod Data Profile Version',
                       '_dec_generic'),
        (0xDF, 0x7E): ('EF_prod Data Location Machine Date Time',
                       '_dec_generic'),
        (0xDF, 0x7E): ('EF_prod Complete',
                       '_dec_generic'),
        (0xFF, 0x21): ('Extended Card Resources Information',
                       '_dec_generic')
        }
    
    GP_OID = [42, 134, 72, 134, 252, 107] # {1 2 840 114283}
    
    def __init__(self):
        # initialize like an UICC object, to get the AID_GP
        UICC.__init__(self)
        self.get_AID_GP()
        if not self.AID_GP:
            log(2, '(GP.__init__) no GP AID found')
        #
        self.Infos  = {}
        # move to the GP specific class
        self.CLA = 0x80
    
    def get_infos(self):
        '''
        self.get_infos() -> None
        
        tries to read GP specific global information from the OPEN domain
        and fills self.FS with results
        '''
        for (p1, p2) in self.FSDesc.keys():
            ret = self.GET_DATA(P1=p1, P2=p2, Le=0)
            self.coms.push(ret)
            if ret[2][0] == 0x6C:
                # file exists
                le  = ret[2][1]
                ret = self.GET_DATA(P1=p1, P2=p2, Le=le)
                self.coms.push(ret)
                if ret[2] == (0x90, 0x00):
                    try:
                        data = BERTLV_extract(ret[3])
                        # must be a single component BER-TLV struct starting 
                        # with the given tag
                        if len(data) != 1 and self.dbg:
                            log(2, '(GP.get_infos) several BER-TLV structures '\
                                   'for tag %.2X.%.2X' % (p1, p2))
                            self.Infos[(p1, p2)] = data
                        else:
                            self.Infos[(p1, p2)] = data[0][1]
                    except:
                        if self.dbg:
                            log(2, '(GP.get_infos) invalid BER-TLV structure '\
                                   'for tag %.2X.%.2X' % (p1, p2))
                        data = ret[3]
    
    def scan_p1p2(self):
        for p1 in range(0, 256):
            for p2 in range(0, 256):
                if (p1, p2) not in self.Infos:
                    ret = self.GET_DATA(P1=p1, P2=p2, Le=0)
                    self.coms.push(ret)
                    if ret[2][0] == 0x6C:
                        # file exists
                        le  = ret[2][1]
                        ret = self.GET_DATA(P1=p1, P2=p2, Le=le)
                        self.coms.push(ret)
                        if ret[2] == (0x90, 0x00):
                            try:
                                data = BERTLV_extract(ret[3])
                            except:
                                data = 'raw: %s' % hexlify(byteToString(ret[3]))
                            if self.dbg:
                                log(3, '> found %.2X.%.2X:\n%r' % (p1, p2, data))
    
    def interpret_infos(self):
        '''
        self.interpret_infos() -> str
        
        prints the results of self.get_infos()
        '''
        if not self.Infos:
            self.get_infos()
        ret = []
        for p1p2 in sorted(self.Infos.keys()):
            data = self.Infos[p1p2]
            if p1p2 in self.FSDesc:
                # trying to decode the data
                try:
                    info = getattr(self, self.FSDesc[p1p2][1])(data)
                except:
                    if self.dbg:
                        log(2, '(GP._dec_*) error while decoding data')
                    info = 'raw: %s' % _pp.pformat(data)
                ret.append('[+] Tag %.2X.%.2X: %s\n%s'\
                           % (p1p2[0], p1p2[1], self.FSDesc[p1p2][0], info))
            else:
                ret.append('[+] Tag %.2X.%.2X: _unknown_\nraw: %s'\
                           % (p1p2[0], p1p2[1], _pp.pformat(data)))
        return ret
    
    def _dec_generic(self, data):
        return pp.pformat(data)
    
    def _dec_oid_try(self, data):
        if all([comp[0] == ['universal', 6, 'OID'] for comp in data]):
            try:
                return ', '.join(['{%s}' % decode_OID(comp[1]) for comp in data])
            except:
                return repr(data)
        else:
            return repr(data)
    
    def _dec_iin(self, data):
        # check how to decode IIN (should be 6 digits ?)
        fmts = '%.2X' * len(data) 
        return fmts % tuple(data)
    
    def _dec_cin(self, data):
        fmts = '%.2X' * len(data) 
        return fmts % tuple(data)
    
    def __dec_oid(self, data):
        if data[:6] != self.GP_OID:
            return '{%s} (invalid)' % decode_OID(data)
        else:
            return '{globalPlatform %s}' % decode_OID(data)[15:]
    
    def _dec_data(self, data):
        # single component with tag 0x73 (Card Recognition Data)
        assert(len(data) == 1 and data[0][0][1] == 19)
        data, dec = data[0][1], []
        # at least 4 mandatory components
        assert(len(data) >= 4)
        #
        # 1st component is OID {globalPlatform 1}
        assert(data[0][0][1] == 6)
        dec.append('Card Recognition Data: %s' % self.__dec_oid(data[0][1]))
        #
        # 2nd component is tag 0, OID {globalPlatform 2 v}
        # 3rd component is tag 3, OID {globalPlatform 3}
        # 4th component is tag 4, OID {globalPlatform 4 scp i}
        # more optional components:
        #   tag 4, OID {globalPlatform 4 scp i}
        #   tag 5, Card configuration details
        #   tag 6, Card / chip details
        #   tag 7, Issuer Security Domain’s Trust Point certificate info
        #   tag 8, Issuer Security Domain certificate info
        #
        for comp in data[1:]:
            tag, val = comp[0][1], comp[1]
            if tag == 0:
                assert(len(val) == 1)
                val = val[0]
                assert(val[0][1] == 6)
                dec.append('Card Management Type and Version: %s'\
                           % self.__dec_oid(val[1]))
            elif tag == 3:
                assert(len(val) == 1)
                val = val[0]
                assert(val[0][1] == 6)
                dec.append('Card Identification Scheme: %s'\
                           % self.__dec_oid(val[1]))
            elif tag == 4:
                for val_comp in val:
                    assert(val_comp[0][1] == 6)
                    dec.append('Secure Channel Protocol: %s'\
                               % self.__dec_oid(val_comp[1]))
            elif tag == 5:
                dec.append('Card Configuration Details: %s'\
                           % self._dec_oid_try(val))
            elif tag == 6:
                dec.append('Card / Chip Details: %s'\
                           % self._dec_oid_try(val))
            elif tag == 7:
                dec.append('ISD Trust Point Cert Info: %s'\
                           % self._dec_oid_try(val))
            elif tag == 8:
                dec.append('ISD Cert Info: %s'\
                           % self._dec_oid_try(val))
        #
        return '\n'.join(['    [+] %s' % s for s in dec])
    
    def _dec_seq_cnt(self, data):
        assert(len(data) == 2)
        return '%i' % (data[1] + (data[0]<<8)) 
    
    def _dec_conf_cnt(self, data):
        assert(len(data) == 2)
        return '%i' % (data[1] + (data[0]<<8)) 
    
    def _dec_cplc(self, data):
        # see globalplatform.h, CPLC data
        return '    [+] IC fabricator: %.2X%.2X\n'\
               '    [+] IC type: %.2X%.2X\n'\
               '    [+] OS id: %.2X%.2X\n'\
               '    [+] OS date: %.2X%.2X\n'\
               '    [+] OS level: %.2X%.2X\n'\
               '    [+] Fabrication date: %.2X%.2X\n'\
               '    [+] IC serial: %.2X%.2X%.2X%.2X\n'\
               '    [+] IC batch: %.2X%.2X\n'\
               '    [+] Module fabricator: %.2X%.2X\n'\
               '    [+] Packaging date: %.2X%.2X\n'\
               '    [+] ICC manufacturer: %.2X%.2X\n'\
               '    [+] IC embedding date: %.2X%.2X\n'\
               '    [+] Pre-personalizer: %.2X%.2X\n'\
               '    [+] IC pre-personalization date: %.2X%.2X\n'\
               '    [+] IC pre-personalization equipment id: %.2X%.2X%.2X%.2X\n'\
               '    [+] IC personalizer: %.2X%.2X\n'\
               '    [+] IC personalization date: %.2X%.2X\n'\
               '    [+] IC presonalization equipment id: %.2X%.2X%.2X%.2X'\
               % tuple(data)
    
