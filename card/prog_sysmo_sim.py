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
# Ki is 16 bytes
Ki_pre = 'abcd016667000'
#
# some more mobile telco info to program into SIM / USIM apps
# MCC: 001, MNC: 01, each BCD encoded, then appended
HPLMN = [0x00, 0xf1, 0x10]

# add at least 7 (dummy) PLMN for being selected by the mobile
PLMNsel = HPLMN \
        + 7 * [0xFF, 0xFF, 0xFF]
#
# HPLMN search period (in minutes)
T_HPLMN = [0x1]
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
# disabling proactive SIM and Menu selection (trying not to receive ugly chinese popups)
SST = [0xFF, 0x33, 0xFF, 0xFF, 0x3F, 0x0, 0x0F, 0x0, 0x30, 0x3C]
# disabling PLMN selector (as EF_PHLMsel is bugged in sysmoUSIM), Advice of Charge,
SST = [0xFF, 0x00, 0xFF, 0xFF, 0x3F, 0x0, 0x0F, 0x0, 0x30, 0x3C]

######################
# sysmoSIM specifics #
######################
# 1) verify CHV 0x0A / 0x0B (ADM CHV) with PIN code DDDDDDDD
# security CHV code for sysmoSIM ADM_4 and ADM_5 profiles
CHV_PROG = [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44]
# or use directly `verify_chv()`
#
# 2) push the following proprietary programming command
# 0x80, 0xD4, 0x02, 0x00, 0x10 + Ki (16 bytes)
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

def verify_chv(sim, chv=CHV_PROG, adm=0xA):
    ret = sim.VERIFY(P2=adm, Data=chv)
    print('VERIFY CHV: %s' % repr(ret))
    if ret[2] == (0x90, 0x00):
        return True
    else:
        return False


class personalize(object):
    '''
    Class to program sysmo-SIM card
    takes a 3 digit serial number as argument to personalize the SIM card.
    
    Makes use of the fixed parameters in this file header:
    ICCID_pre, IMSI_pre, Ki_pre,
    SMSP, HPLMN, PLMNsel, SST, SPN
    '''
    #
    def __init__(self, serial_number='000'):
        # prepare data to write into the card
        if not len(serial_number) == 3 or not serial_number.isdigit():
            print('must provided a 3 digits distinct serial number')
            raise() 
        self.ICCID = ICCID_pre + serial_number + str(compute_luhn(ICCID_pre + serial_number))
        self.IMSI  = IMSI_pre + serial_number
        self.Ki    = Ki_pre + serial_number
        # verify parameters
        if len(self.Ki) != 16:
            print('[-] bad length for Ki')
            raise()
        # program key
        if self.program_key() != 0:
            return
        # program files
        if self.program_files() != 0:
            return
        #
        if self.test_identification() != 0:
            return
        #
        # and print results
        print('[+] sysmoSIM card personalization done and tested successfully:')
        print('%s;%s;0x%s;' % (self.ICCID, self.IMSI, hexlify(self.Ki)))
    
    def program_files(self):
        # program SIM with SMSP and HMPLN infos
        #
        sim = SIM()
        verify_chv(sim, chv=CHV_PROG, adm=0x5)
        #
        # go to ICCID and update it
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x2F, 0xE2])
        ret = sim.UPDATE_BINARY(0, 0, encode_ICCID(self.ICCID))
        print('Writing ICCID: %s' % ret)
        #
        # go to IMSI and update it
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x20])
        sim.SELECT_FILE(0, 0, [0x6F, 0x07])
        ret = sim.UPDATE_BINARY(0, 0, encode_IMSI(self.IMSI))
        print('Writing IMSI: %s' % ret)
        #
        # go to SMSP address and update the 1st record for SMSP
        # this is the absolute address for SIM application
        # USIM app addr for SMSP is only a symlink to it
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x10])
        sim.SELECT_FILE(0, 0, [0x6F, 0x42])
        ret = sim.UPDATE_RECORD(1, 4, SMSP)
        print('Writing SMSP: %s' % ret)
        #
        # go to HPLMN search period file
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x20])
        sim.SELECT_FILE(0, 0, [0x6F, 0x31])
        ret = sim.UPDATE_BINARY(0, 0, T_HPLMN)
        print('Writing HPLMN selection search period: %s' % ret)
        #
        # go to PLMNsel address and update binary string for HPLMN
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x20])
        sim.SELECT_FILE(0, 0, [0x6F, 0x30])
        ret = sim.UPDATE_BINARY(0, 0, PLMNsel)
        print('Writing PLMN selector: %s' % ret)
        #
        # go to SST address and update the service table
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x20])
        sim.SELECT_FILE(0, 0, [0x6F, 0x38])
        ret = sim.UPDATE_BINARY(0, 0, SST)
        print('Writing SIM Services Table: %s' % ret)
        #
        # go to SPN address and update Service Provider Name
        sim.SELECT_FILE(0, 0, [0x3F, 0x00])
        sim.SELECT_FILE(0, 0, [0x7F, 0x20])
        sim.SELECT_FILE(0, 0, [0x6F, 0x46])
        ret = sim.UPDATE_BINARY(0, 0, SPN)
        print('Writing Service Provider Name: %s' % ret)
        #
        sim.disconnect()
        return 0
    
    def program_key(self):
        # 2) push the following proprietary programming command
        # 0x80, 0xD4, 0x02, 0x00, 0x10 + Ki (16 bytes)
        i = ISO7816()
        ki = stringToByte(self.Ki)
        ret = i.sr_apdu(apdu=[0x80, 0xD4, 0x02, 0x00, len(ki)]+ki)
        i.disconnect()
        if ret[2] != (0x90, 0x00):
            print('Writing Ki failed:\n%s' % repr(ret))
            return 1
        print('[+] Ki written')
        return 0
    
    def test_identification(self):
        s = SIM()
        self.ICCID = s.get_ICCID()
        #s.disconnect()
        #s = SIM()
        self.IMSI = s.get_imsi()
        s.disconnect()
        print('[+] SIM identification:\nICCID: %s\nIMSI: %s'  \
              % (self.ICCID, self.IMSI))
        if not self.ICCID or not self.IMSI:
            print('[-] identification error')
            return 1
        return 0
