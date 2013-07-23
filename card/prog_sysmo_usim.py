# -*- coding: UTF-8 -*-
"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2013 Benoit Michau, ANSSI

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
################################
# script to program sysmoUSIM  #
# with fixed parameters        #
# and a 3 digits serial number #
################################

from card.ICC import *
from card.SIM import SIM
from card.USIM import USIM
from binascii import hexlify
from struct import unpack, pack
from random import _urandom as urand
from CryptoMobile.Milenage import *
from libmich.formats.L3Mobile_IE import ID

ISO7816.dbg = 0
UICC.dbg = 0

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
#
# some more mobile telco info to program into SIM / USIM apps
# MCC: 001, MNC: 01, each BCD encoded, then appended
HPLMN = [0x00, 0xf1, 0x10]

# add at least 7 (dummy) PLMN for being selected by the mobile
PLMNsel = HPLMN \
        + 7 * [0xFF, 0xFF, 0xFF]
#
# HPLMN search period (in minutes)
T_HPLMN = [0x2]
#
# Service Provider Name (display condition + string of 15 bytes) 
SPN = [0b1] + [ord(c) for c in 'Test Telecom'] + 4*[0xFF]
#
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
#
# SST : 51.011, 10.3.7, SIM Services Table
# original sysmoUSIM SST: [0xFF, 0x33, 0xFF, 0xFF, 0x3F, 0x0, 0x3F, 0x03, 0x30, 0x3C]
# disabling proactive SIM and Menu selection (to not receive ugly chinese popups)
SST = [0xFF, 0x33, 0xFF, 0xFF, 0x3F, 0x0, 0x0F, 0x0, 0x30, 0x3C]
# disabling PLMN selector (as EF_PHLMsel is bugged in sysmoUSIM), Advice of Charge,
SST = [0xFF, 0x0, 0xFF, 0xFF, 0x3F, 0x0, 0x0F, 0x0, 0x30, 0x3C]

#######################
# sysmoUSIM specifics #
#######################
# 1) verify CHV 0x0A (ADM CHV) with PIN code 32213232
# security CHV code for sysmoUSIM ADM_4 profile
CHV_PROG = [0x33, 0x32, 0x32, 0x31, 0x33, 0x32, 0x33, 0x32]
# or use directly `verify_chv()`
#
# 2) push the following proprietary programming command
# 0x00 0x99 0x00 0x00 0x33 +
# K (16 bytes) +
# OPc (16 bytes) +
# ICCID (10 bytes) +
# IMSI (9 bytes)
#
# 3) update any file from the DF_Telecom or DF_GSM directory
#

def encode_ICCID(digit_str=''):
    # BCD encoding
    # max length is 10 bytes / 19 digits
    # padding with 0xF
    if not digit_str.isdigit():
        print('[-] we need a string of digits')
        return
    # ensure its less or equal than 10 bytes, and pad it
    digit_str = digit_str[:19] + 'F'*(20-len(digit_str[:19]))
    # return the BCD encoded vector
    return [(int(digit_str[i+1],16)<<4)+int(digit_str[i],16) \
            for i in range(0, 20, 2)]

def encode_IMSI(digit_str=''):
    # Length + IMSI ID as vector
    if not digit_str.isdigit():
        print('[-] we need a string of digits')
        return
    return [0x08] + stringToByte(str(ID(val=digit_str[:16], type='IMSI')))

def program_vec(K=[], OPc=[], ICCID=[], IMSI=[]):
    # work with ISO class
    c = ISO7816(CLA=0)
    # verify CHV used for programming sysmoUSIM
    #ret = c.VERIFY(P2=0xA, Data=CHV_PROG)
    #if ret[2] == (0x90, 0x00):
    if verify_chv(c, chv='32213232', adm=0xA):
        # now program with instruction 0x99
        apdu = [0x00, 0x99, 0x00, 0x00, 0x33] + K + OPc + ICCID + IMSI
        ret = c.sr_apdu(apdu)
        if ret[2] == (0x90, 0x00):
            print('[+] programmation succeeded:\n%s' % ret)
            c.disconnect()
            return 0
    print('[-] programmation failed\n%s' % c.coms())
    print c.coms
    c.disconnect()
    return 1

def program_str(K=16*'\0', OPc=16*'\0', ICCID=10*'\0', IMSI=9*'\0'):
    [K, OPc, ICCID, IMSI] = map(stringToByte, [K, OPc, ICCID, IMSI])
    return program_vec(K, OPc, ICCID, IMSI)

def sqn_to_str(i=0):
    if type(i) != int: raise()
    return '\0\0' + pack('!I', i)

def str_to_sqn(s=6*'\0'):
    if len(s) != 6: raise()
    r = unpack('!HI', s)
    return (r[0]<<32) + r[1]

def verify_chv(uicc, chv='32213232', adm=0xA):
    apdu = [0x30+int(d) for d in chv if d.isdigit()]
    ret = uicc.VERIFY(P2=adm, Data=apdu)
    if ret[2] == (0x90, 0x00):
        return True
    else:
        return False

def program_files(uicc):
    # program SIM with SMSP and HMPLN infos
    #
    # update record for SMSP (7f, 10, 6f, 42)
    # update binary for HPLMN (7f, 20, 6f, 30) -> 1 PLMN (3 bytes) + 7*3 '\xFF'
    # PLMN_sel ?
    #c = ISO7816(CLA=0)
    verify_chv(uicc, chv='32213232', adm=0xA)
    #
    # go to SMSP address and update the 1st record for SMSP
    # this is the absolute address for SIM application
    # USIM app addr for SMSP is only a symlink to it
    uicc.SELECT_FILE(0, 4, [0x7F, 0x10])
    uicc.SELECT_FILE(0, 4, [0x6F, 0x42])
    ret = uicc.UPDATE_RECORD(1, 4, SMSP)
    print('Writing SMSP: %s' % ret)
    #
    # go to HPLMN search period file
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x7F, 0x20])
    uicc.SELECT_FILE(0, 4, [0x6F, 0x31])
    ret = uicc.UPDATE_BINARY(0, 0, T_HPLMN)
    print('Writing HPLMN selection search period: %s' % ret)
    #
    # go to PLMNsel address and update binary string for HPLMN
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x7F, 0x20])
    uicc.SELECT_FILE(0, 4, [0x6F, 0x30])
    ret = uicc.UPDATE_BINARY(0, 0, PLMNsel)
    print('Writing PLMN selector: %s' % ret)
    #
    # go to SST address and update the service table
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x7F, 0x20])
    uicc.SELECT_FILE(0, 4, [0x6F, 0x38])
    ret = uicc.UPDATE_BINARY(0, 0, SST)
    print('Writing SIM Services Table: %s' % ret)
    #
    # go to SPN address and update Service Provider Name
    uicc.SELECT_FILE(0, 4, [0x3F, 0x00])
    uicc.SELECT_FILE(0, 4, [0x7F, 0x20])
    uicc.SELECT_FILE(0, 4, [0x6F, 0x46])
    ret = uicc.UPDATE_BINARY(0, 0, SPN)
    print('Writing Service Provider Name: %s' % ret)


class personalize(object):
    '''
    Class to program sysmo-USIM card
    takes a 3 digit serial number as argument to personalize the USIM card.
    
    Makes use of the fixed parameters in this file header:
    ICCID_pre, IMSI_pre, Ki_pre, OP,
    SMSP, HPLMN, PLMNsel, SST, SPN
    '''
    #
    # current auth counter for the USIM to personalize:
    # if you do not know it, just comment the following attribute
    # it seems sysmoUSIM are shipped with a counter value around 31
    SQN = 1
    
    def __init__(self, serial_number='000'):
        # prepare data to write into the card
        if not len(serial_number) == 3 or not serial_number.isdigit():
            print('must provided a 3 digits distinct serial number')
            raise()
        self.ICCID      = ICCID_pre + serial_number
        self.ICCID     += str(compute_luhn(self.ICCID))
        self.IMSI       = IMSI_pre + serial_number
        self.K          = K_pre + serial_number
        self.Milenage   = Milenage(OP)
        self.OPc        = make_OPc(self.K, OP)
        # verify parameters
        if map(len, [self.K, self.OPc]) != [16, 16]:
            print('[-] bad length for K or OPc')
            raise()
        # write on the card
        if self.program_card() != 0:
            return
        if self.test_identification() != 0:
            return
        self.auth_test = 0
        if self.test_authentication() != 0:
            return
        # finally add some files for infra (SMSP, HPLMN)
        u = UICC()
        program_files(u)
        u.disconnect()
        # and print results
        print('[+] sysmoUSIM card personalization done and tested successfully:')
        print('%s;%s;0x%s;0x%s' % (self.ICCID, self.IMSI, \
                               hexlify(self.K), hexlify(self.OPc)))
    
    def program_card(self):
        return program_vec(K = stringToByte(self.K), \
                           OPc = stringToByte(self.OPc), \
                           ICCID = encode_ICCID(self.ICCID), \
                           IMSI = encode_IMSI(self.IMSI))
        
    def test_identification(self):
        u = UICC()
        self.ICCID = u.get_ICCID()
        u.disconnect()
        u = USIM()
        self.IMSI = u.get_imsi()
        print('[+] USIM identification:\nICCID: %s\nIMSI: %s'  \
              % (self.ICCID, self.IMSI))
        u.disconnect()
        if not self.ICCID or not self.IMSI:
            print('[-] identification error')
            return 1
        return 0
    
    def test_authentication(self):
        if self.auth_test >= 2:
            return 1
        u = USIM()
        # prepare auth challenge
        self.RAND = urand(16) # challenge is 128 bits
        if not hasattr(self, 'SQN'):
            self.SQN = 0 # default SQN is 0, coded on 48 bits
        AMF = 2*'\0' # management field, unneeded, left blank
        # compute Milenage functions
        XRES, CK, IK, AK = self.Milenage.f2345( self.K, self.RAND )
        MAC_A = self.Milenage.f1(self.K, self.RAND, sqn_to_str(self.SQN), AMF)
        AUTN = xor_string(sqn_to_str(self.SQN), AK) + AMF + MAC_A
        # run auth data on the USIM
        ret = u.authenticate(stringToByte(self.RAND), stringToByte(AUTN), '3G')
        # check results (and pray)
        if ret == None:
            print('[-] authenticate() failed; something wrong happened, '\
                  'maybe during card programmation ?')
        elif len(ret) == 1:
            print('[-] sync failure during authenticate(); unmasking counter')
            auts = byteToString(ret[0])
            ak = self.Milenage.f5star(self.K, self.RAND)
            self.SQN = str_to_sqn(xor_string(auts, ak)[:6])
            print('[+] auth counter value in USIM: %i' % self.SQN)
            self.SQN += 1
            print('[+] retrying authenticate() with SQN: %i' % self.SQN)
            u.disconnect()
            self.test_authentication()
        elif len(ret) in (3, 4):
            # RES, CK, IK(, Kc)
            if ret[0:3] == map(stringToByte, [XRES, CK, IK]):
                print('[+] 3G auth successful with SQN: %i\n' \
                      'increment it from now' % self.SQN)
                print('[+] USIM secrets:\nOPc: %s\nK: %s' \
                      % (hexlify(self.OPc), hexlify(self.K)))
            else:
                print('[-] 3G auth accepted on the USIM, ' \
                      'but not matching auth vector generated: strange!')
                print('card returned:\n%s' % ret)
        u.disconnect()
        return 0
        
