# -*- coding: UTF-8 -*-
"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2017 Benoit Michau, ANSSI

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
####################################
# script to program sysmoUSIM-SJS1 #
# with fixed parameters            #
# and a 3 digits serial number     #
####################################

from card.ICC  import *
from card.SIM  import SIM
from card.USIM import USIM
from binascii  import hexlify, unhexlify
from struct    import unpack, pack
from CryptoMobile.Milenage import Milenage, make_OPc
from CryptoMobile.utils    import xor_buf

ISO7816.dbg = 0
UICC.dbg = 0

def encode_bcd_byte(dig):
    if len(dig) % 2:
        dig += 'F'
    return [(int(dig[i+1], 16)<<4)+int(dig[i], 16) for i in range(0, len(dig), 2)]


##################
# fixed prefixes #
##################
# ICCID is 19 digits max:
# 89 (telco) | 33 (country code) | issuer id | serial number | luhn digit
ICCID_pre = '8933016667000'
# IMSI is 15 or 16 digits
# 001 (mcc) | 01 (mnc) | subscriber id
IMSI_pre = '001016667000'
# K and OP are 16 bytes
Ki_pre = 'abcd016667000'
OP = 'ffffffffffffffff'

# some more mobile telco info to program into SIM / USIM apps
# MCC: 001, MNC: 01, each BCD encoded, then appended
HPLMN = [0x00, 0xf1, 0x10]

# add at least 7 (dummy) PLMN for being selected by the mobile
PLMNsel = HPLMN + \
          7 * [0xFF, 0xFF, 0xFF]

# HPLMN search period (in minutes)
T_HPLMN = [0x2]

# Service Provider Name (display condition + string of 15 bytes) 
SPN = [0b1] + [ord(c) for c in 'Test Telecom'] + 4*[0xFF]

# WARNING: SJS1 cards have a different file format for SMS, this does not work
# TODO: make it work properly
# SMS parameters
# SMSP : 51.011, 10.5.6, addr = (6F, 42), type is linear fixed
_al = [ord(c) for c in 'TestTel\xFF\xFF\xFF\xFF\xFF'] # 12 bytes exactly, for alpha
_p_ind = [0xF5]  # Parameters indicator : only SMSC phone number and DCS
_dest_addr = 12*[0xFF] # blank TP-Destination address
_sc_addr = [0x5, 0x81, 0x0, 0x01, 0x66, 0x76, 0xff, 0xff, 0xff, 0xff, 0xff, \
           0xff] # SMSC phone number: '016667' (indexes 3, 4 and 5)
_pid = [0xFF] # blank protocol ID
_dcs = [0x00] # Data Coding Scheme : classic GSM 7-bit alphabet
_val = [0xFF] # blank validity period
SMSP = _al + _p_ind + _dest_addr + _sc_addr + _pid + _dcs + _val

# SST : 51.011, 10.3.7, SIM Services Table
# original sysmoUSIM-SJS1 SST: [0xff, 0x3f, 0xff, 0xff, 0x3f, 0x0, 0x3f, 0x1f, 0xf0, 0xc, 0x0, 0xc0, 0xf0, 0x0, 0x0]
# UST : 31.102, 4.2.8, USIM Services Table
# original sysmoUSIM-SJS1 UST: [0x9e, 0x6b, 0x1d, 0xfc, 0x67, 0xf6, 0x58, 0x0, 0x0]

############################
# sysmoUSIM-SJS1 specifics #
############################

# 1) verify CHV 0x0A (ADM CHV) with ADM code given for the selected card
# use directly `verify_chv()`
#
# 2) write the required (U)SIM values at the following addresses:
# ICCID: MF / (0x2f, 0xe2), std addr
# IMSI : DF_GSM / (0x6f, 0x07), std addr
# Ki   : DF_GSM / (0x00, 0xff), proprietary addr
# OPc  : DF_GSM / (0x00, 0xf7), proprietary addr, OPc needs to be prefixed with byte 0x01
#
# 3) update any file from the DF_Telecom or DF_GSM directory


def encode_iccid(digit_str):
    # BCD encoding
    # max length is 10 bytes / 19 digits
    # padding with 0xF
    if not digit_str.isdigit():
        raise(Exception('ICCID: string of (up to 19) digits required, %r' % digit_str))
    # ensure its less or equal than 10 bytes, and pad it
    digit_str = digit_str[:19] + 'F'*(20-len(digit_str[:19]))
    # return the BCD encoded vector
    return encode_bcd_byte(digit_str)


def encode_imsi(digit_str):
    # Length + IMSI ID as vector
    if not digit_str.isdigit():
        raise(Exception('IMSI: string of (up to 16) digits required, %r' % digit_str))
    if len(digit_str) % 2:
        # odd length
        odd = 1
    else:
        odd = 0
    b1 = (int(digit_str[0])<<4) + (odd<<3) + 1
    return [0x08, b1] + encode_bcd_byte(digit_str[1:])


def sqn_to_str(sqn):
    if not isinstance(sqn, int) or not 0 <= sqn < (1<<32):
        raise(Exception('SQN: uint32 required, %r' % sqn))
    return b'\0\0' + pack('!I', sqn)


def str_to_sqn(sqnb):
    if not isinstance(sqnb, bytes) or len(sqnb) != 6:
        raise(Exception('SQN buffer: 6-bytes buffer required, %r' % sqnb))
    r = unpack('!HI', sqnb)
    return (r[0]<<32) + r[1]


def verify_chv(uicc, chv, adm=0xA):
    apdu = [0x30+int(d) for d in chv]
    ret = uicc.VERIFY(P2=adm, Data=apdu)
    if ret[2] == (0x90, 0x00):
        return True
    else:
        return False


def select_dfgsm(uicc):
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x7F, 0x20])


def program_files(uicc, ADM, ICCID, IMSI, Ki, OPc):
    # program SIM with given arguments: ICCID, IMSI, Ki, OPc
    # and fixed parameters: HPLMN, PLMNsel, T_HPLMN, SPN and SMSP
    #
    # update record for SMSP (7f, 10, 6f, 42)
    # update binary for HPLMN (7f, 20, 6f, 30) -> 1 PLMN (3 bytes) + 7*3 '\xFF'
    
    # 1) ADM CHV
    if not ADM.isdigit() or len(ADM) != 8:
        raise(Exception('ADM: string of 8 digits required'))
    if not verify_chv(uicc, chv=ADM, adm=0xA):
        print('error: ADM code refused')
        return 0
    
    # 2) ICCID
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x2F, 0xE2])
    ret = uicc.UPDATE_BINARY(0, 0, encode_iccid(ICCID))
    print('Writing ICCID: %s' % ret)
    
    # 3) IMSI
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x6F, 0x07])
    ret = uicc.UPDATE_BINARY(0, 0, encode_imsi(IMSI))
    print('Writing IMSI: %s' % ret)
    
    # 4) Ki
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x00, 0xFF])
    ret = uicc.UPDATE_BINARY(0, 0, stringToByte(Ki))
    print('Writing Ki: %s' % ret)
    
    # 5) OPc
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x00, 0xF7])
    ret = uicc.UPDATE_BINARY(0, 0, [0x01] + stringToByte(OPc))
    print('Writing OPc: %s' % ret)
    
    # 6) T_HPLMN
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x6F, 0x31])
    ret = uicc.UPDATE_BINARY(0, 0, T_HPLMN)
    print('Writing HPLMN selection search period: %s' % ret)
    
    # 7) PLMNsel
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x6F, 0x30])
    ret = uicc.UPDATE_BINARY(0, 0, PLMNsel)
    print('Writing PLMN selector: %s' % ret)
    
    # 8) SPN
    select_dfgsm(uicc)
    uicc.SELECT_FILE(0, 4, [0x6F, 0x46])
    ret = uicc.UPDATE_BINARY(0, 0, SPN)
    print('Writing Service Provider Name: %s' % ret)
    
    # 9) SST
    #select_dfgsm(uicc)
    #uicc.SELECT_FILE(0, 4, [0x6F, 0x38])
    #ret = uicc.UPDATE_BINARY(0, 0, SST)
    #print('Writing SIM Services Table: %s' % ret)
    
    # 10) SMSP
    # go to SMSP address and update the 1st record for SMSP
    # this is the absolute address for SIM application
    # USIM app addr for SMSP is only a symlink to it
    #uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    #uicc.SELECT_FILE(0, 4, [0x7F, 0x10])
    #uicc.SELECT_FILE(0, 4, [0x6F, 0x42])
    #ret = uicc.UPDATE_RECORD(1, 4, SMSP)
    #print('Writing SMSP: %s' % ret)
    
    return 0


class personalize(object):
    '''
    Class to program sysmo-USIM-SJS1 card
    takes the ADM code of the card (str of digits)
    and	a 3 digit serial number as argument to personalize the USIM card.
    
    Makes use of the fixed parameters in this file header:
    ICCID_pre, IMSI_pre, Ki_pre, OP,
    HPLMN, PLMNsel, SPN
    '''
    
    def __init__(self, ADM, serial_number='000', zero=False):
        # prepare data to write into the card
        if not len(serial_number) == 3 or not serial_number.isdigit():
            raise(Exception('serial: 3-digits required'))
        self.ICCID      = ICCID_pre + serial_number
        self.ICCID     += str(compute_luhn(self.ICCID))
        self.IMSI       = IMSI_pre + serial_number
        if zero:
            OP              = 16 * b'\0'
            self.K          = 16 * b'\0'
            self.Milenage   = Milenage(OP)
            self.OPc        = make_OPc(self.K, OP)
        else:
            self.K          = Ki_pre + serial_number
            self.Milenage   = Milenage(OP)
            self.OPc        = make_OPc(self.K, OP)
        # verify parameters
        if len(self.K) != 16 or len(self.OPc) != 16:
            raise(Exception('K / OPc: 16-bytes buffer required'))
        #
        # write data on the card
        u = UICC()
        program_files(u, ADM, self.ICCID, self.IMSI, self.K, self.OPc)
        u.disconnect()
        #
        if self.test_identification() != 0:
            return
        #
        self._auth = 0
        if self.test_authentication() != 0:
            return
        #
        # and print results
        print('[+] sysmoUSIM-SJS1 card personalization done and tested successfully:')
        print('ICCID ; IMSI ; K ; OPc')
        print('%s;%s;0x%s;0x%s' % (self.ICCID, self.IMSI, hexlify(self.K), hexlify(self.OPc)))
    
    def test_identification(self):
        u = UICC()
        iccid = u.get_ICCID()
        u.disconnect()
        u = USIM()
        imsi = u.get_imsi()
        u.disconnect()
        #
        if not iccid or not imsi:
            raise(Exception('identification test error'))
            return 1
        else:
            print('[+] USIM identification:\nICCID: %s\nIMSI: %s' % (iccid, imsi))
            return 0
    
    def test_authentication(self):
        if self._auth > 2:
            return 1
        #
        # prepare dummy 128 bits auth challenge
        if not hasattr(self, 'RAND'):
            self.RAND = 16*b'\x44'
        if not hasattr(self, 'SQN'):
            # default SQN is 0, coded on 48 bits
            self.SQN = 0
        # management field, unneeded, left blank
        AMF = b'\0\0'
        #
        # compute Milenage functions
        XRES, CK, IK, AK = self.Milenage.f2345( self.K, self.RAND )
        MAC_A = self.Milenage.f1(self.K, self.RAND, sqn_to_str(self.SQN), AMF)
        AUTN = xor_buf(sqn_to_str(self.SQN), AK) + AMF + MAC_A
        #
        # run auth data on the USIM
        self.U = USIM()
        ret = self.U.authenticate(stringToByte(self.RAND), stringToByte(AUTN), '3G')
        self.U.disconnect()
        self._auth += 1
        #
        # check results (and pray)
        if ret == None:
            print('[-] authenticate() failed, something wrong happened')
            del self.RAND
            return 1
        #
        elif len(ret) == 1:
            print('[-] sync failure during authenticate() with SQN %i, unmasking counter' % self.SQN)
            auts = byteToString(ret[0])
            ak = self.Milenage.f5star(self.K, self.RAND)
            self.SQN = str_to_sqn(xor_buf(auts, ak)[:6])
            print('[+] SQN counter value in USIM: %i' % self.SQN)
            self.SQN += 1<<5
            print('[+] retrying authenticate() with SQN: %i' % self.SQN)
            del self.RAND
            return self.test_authentication()
        #
        elif len(ret) in (3, 4):
            # RES, CK, IK(, Kc)
            if ret[0:3] == map(stringToByte, [XRES, CK, IK]):
                print('[+] 3G auth successful with SQN: %i\nincrement it from now' % self.SQN)
                print('[+] USIM secrets:\nOPc: %s\nK: %s' % (hexlify(self.OPc), hexlify(self.K)))
            else:
                print('[-] 3G auth accepted on the USIM, but not matching auth vector generated: strange!')
                print('card returned:\n%s' % ret)
            del self.RAND
            return 0
        #
        else:
            print('[-] undefined auth error')
            del self.RAND
            return 1
