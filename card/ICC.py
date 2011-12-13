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
# Python library to work on
# smartcard defined with ISO 7816
#
# Specially designed SIM and USIM class
# for ETSI / 3GPP cards
#
# needs pyscard from:
# http://pyscard.sourceforge.net/
#################################

# classic python modules
import os
import re

# smartcard python modules from pyscard
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.ATR import ATR
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString

from card.utils import *
        
###########################################################
# ISO7816 class with attributes and methods as defined 
# by ISO-7816 part 4 standard for smartcard 
###########################################################

class ISO7816(object):
    '''
    define attributes, methods and facilities for ISO-7816-4 standard smartcard
    
    use self.dbg = 1 or more to print live debugging information
    standard instructions codes available in "INS_dic" class dictionnary
    standard file tags available in "file_tags" class dictionnary
    '''
    
    dbg = 0
    
    INS_dic = {
        0x04 : 'DEACTIVATE FILE',
        0x0C : 'ERASE RECORD(S)',
        0x0E : 'ERASE BINARY',
        0x0F : 'ERASE BINARY',
        0x10 : 'TERMINAL PROFILE',
        0x12 : 'FETCH',
        0x14 : 'TERMINAL RESPONSE',
        0x20 : 'VERIFY',
        0x21 : 'VERIFY',
        0x22 : 'MANAGE SECURITY ENVIRONMENT',
        0x24 : 'CHANGE PIN',
        0x26 : 'DISABLE PIN',
        0x28 : 'ENABLE PIN',
        0x2A : 'PERFORM SECURITY OPERATION',
        0x2C : 'UNBLOCK PIN',
        0x32 : 'INCREASE',
        0x44 : 'ACTIVATE FILE',
        0x46 : 'GENERATE ASYMETRIC KEY PAIR',
        0x70 : 'MANAGE CHANNEL',
        0x73 : 'MANAGE SECURE CHANNEL',
        0x75 : 'TRANSACT DATA',
        0x84 : 'GET CHALLENGE',
        0x86 : 'GENERAL AUTHENTICATE',
        0x87 : 'GENERAL AUTHENTICATE',
        0x88 : 'INTERNAL AUTHENTICATE',
        0x89 : 'AUTHENTICATE',
        0xA0 : 'SEARCH BINARY',
        0xA1 : 'SEARCH BINARY',
        0xA2 : 'SEARCH RECORD',
        0xA4 : 'SELECT FILE',
        0xAA : 'TERMINAL CAPABILITY',
        0xB0 : 'READ BINARY',
        0xB1 : 'READ BINARY',
        0xB2 : 'READ RECORD(S)',
        0xB3 : 'READ RECORD(S)',
        0xC0 : 'GET RESPONSE',
        0xC2 : 'ENVELOPE',
        0xC3 : 'ENVELOPE',
        0xCA : 'RETRIEVE DATA',
        0xCB : 'RETRIEVE DATA',
        0xD2 : 'WRITE RECORD',
        0xD6 : 'UPDATE BINARY',
        0xD7 : 'UPDATE BINARY',
        0xDA : 'SET DATA',
        0xDB : 'SET DATA',
        0xDC : 'UPDATE RECORD',
        0xDD : 'UPDATE RECORD',
        0xE0 : 'CREATE FILE',
        0xE2 : 'APPEND RECORD',
        0xE4 : 'DELETE FILE',
        0xE6 : 'TERMINATE DF',
        0xE8 : 'TERMINATE EF',
        0xF2 : 'STATUS',
        0xFE : 'TERMINATE CARD USAGE',
        }
               
    file_tags = {
        0x80 : 'Size',
        0x81 : 'Length',
        0x82 : 'File Descriptor',
        0x83 : 'File Identifier',
        0x84 : 'DF Name',
        0x85 : 'Proprietary no-BERTLV',
        0x86 : 'Proprietary Security Attribute',
        0x87 : 'EF with FCI extension',
        0x88 : 'Short File Identifier',
        0x8A : 'Life Cycle Status',
        0x8B : 'Security Attributes ref to expanded',
        0x8C : 'Security Attributes compact',
        0x8D : 'EF with Security Environment',
        0x8E : 'Channel Security Attribute',
        0xA0 : 'Security Attribute for DO',
        0xA1 : 'Proprietary Security Attribute',
        0xA2 : 'DO Pairs',
        0xA5 : 'Proprietary BERTLV',
        0xAB : 'Security Attribute expanded',
        }     
               
    def __init__(self, CLA=0x00):
        '''
        connect smartcard and defines class CLA code for communication
        uses "pyscard" library services
        
        creates self.CLA attribute with CLA code
        and self.coms attribute with associated "apdu_stack" instance
        '''
        cardtype = AnyCardType()
        cardrequest = CardRequest(timeout=1, cardType=cardtype)
        self.cardservice = cardrequest.waitforcard()
        self.cardservice.connection.connect()
        self.reader = self.cardservice.connection.getReader()
        self.ATR = self.cardservice.connection.getATR()
        
        self.CLA = CLA
        self.coms = apdu_stack()
    
    def disconnect(self):
        '''
        disconnect smartcard: stops the session
        uses "pyscard" library service
        '''
        self.cardservice.connection.disconnect()
    
    def define_class(self, CLA=0x00):
        '''
        define smartcard class attribute for APDU command
        override CLA value defined in class initialization
        '''
        self.CLA = CLA
    
    def ATR_scan(self, smlist_file="/usr/share/pcsc/smartcard_list.txt"):
        '''
        print smartcard info retrieved from AnswerToReset 
        thanks to pyscard routine
        
        if pcsc_scan is installed,
        use the signature file passed as argument for guessing the card
        '''
        print '\nsmartcard reader: ', self.reader
        if self.ATR != None:
            print "\nsmart card ATR is: %s" % toHexString(self.ATR)
            print 'ATR analysis: '
            print ATR(self.ATR).dump()
            print '\nhistorical bytes: ', \
                toHexString(ATR(self.ATR).getHistoricalBytes())
            ATRcs = ATR(self.ATR).getChecksum()
            if ATRcs :
                print 'checksum: ', "0x%X" % ATRcs
            else:
                print 'no ATR checksum'
            print "\nusing pcsc_scan ATR list file: %s" % smlist_file
            if os.path.exists(smlist_file):
                smlist = open(smlist_file).readlines()
                ATRre = re.compile('(^3[BF]){1}.{1,}$')
                ATRfinger = ''
                j = 1
                for i in range(len(smlist)):
                    if ATRre.match(smlist[i]):       
                        if re.compile(smlist[i][:len(smlist[i])-1]).\
                        match(toHexString(self.ATR)):
                            while re.compile('\t.{1,}').match(smlist[i+j]):
                                ATRfinger += smlist[i+j][1:]
                                j += j
                if ATRfinger == '' :
                    print "no ATR fingerprint found in file: %s" % smlist_file
                else:
                    print "smartcard ATR fingerprint:\n%s" % ATRfinger
            else:
                print "%s file not found" % smlist_file
    
    def sw_status(self, sw1, sw2):
        '''
        sw_status(sw1=int, sw2=int) -> string
        
        SW status bytes interpretation as defined in ISO-7816 part 4 standard
        helps to speak and understand with the smartcard!
        '''
        status = 'undefined status'
        if sw1 == 0x90 and sw2 == 0x00: status = 'normal processing: ' \
            'command accepted: no further qualification'       
        elif sw1 == 0x61: status = 'normal processing: %i bytes ' \
            'still available' % sw2
        elif sw1 == 0x62:
            status = 'warning processing: state of non-volatile '\
                     'memory unchanged'
            if   sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x81: status += ': part of returned data may' \
                'be corrupted'
            elif sw2 == 0x82: status += ': end of file/record reached ' \
                'before reading Le bytes' 
            elif sw2 == 0x83: status += ': selected file invalidated'
            elif sw2 == 0x84: status += ': FCI not formatted'
            elif sw2 == 0x85: status += ': selected file in termination state'
            elif sw2 == 0x86: status += ': no input data available ' \
                'from a sensor on the card'
            elif 0x01 < sw2 < 0x81: status += ': card has %s bytes pending' \
                % toHexString([sw2])[1]
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x63:
            status = 'warning processing: state of non-volatile memory changed'
            if   sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x81: status += ': file filled up by the last write'
            elif 0xC0 <= sw2 <= 0xCF: status += ': counter provided by %s' \
                % toHexString([sw2])[1]
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x64:
            status = 'execution error: state of non-volatile memory unchanged'
            if sw2 == 0x01: status += ': immediate response expected ' \
                'by the card'
            elif 0x01 < sw2 < 0x81:  status += ': command aborted ' \
                'by the card, recovery of %s bytes is needed' \
                % toHexString([sw2])
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x65:
            status = 'execution error: state of non-volatile memory changed'
            if   sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x81: status += ': memory failure'
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x66: status = 'execution error: reserved for ' \
            'security-related issues'
        elif sw1 == 0x67 and sw2 == 0x00: status = 'checking error: ' \
            'wrong length (P3 parameter)'
        elif sw1 == 0x68:
            status = 'checking error: functions in CLA not supported'
            if   sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x81: status += ': logical channel not supported'
            elif sw2 == 0x82: status += ': secure messaging not supported'
            elif sw2 == 0x83: status += ': last command of the chain expected'
            elif sw2 == 0x84: status += ': command chaining not supported'
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x69:
            status = 'checking error: command not allowed'
            if sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x81: status += ': command incompatible with ' \
                'file structure'
            elif sw2 == 0x82: status += ': security status not satisfied'
            elif sw2 == 0x83: status += ': authentication method blocked'
            elif sw2 == 0x84: status += ': referenced data invalidated'
            elif sw2 == 0x85: status += ': conditions of use not satisfied'
            elif sw2 == 0x86: status += ': command not allowed (no current EF)'
            elif sw2 == 0x87: status += ': expected SM data objects missing'
            elif sw2 == 0x88: status += ': SM data objects incorrect'
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x6A:
            status = 'checking error: wrong parameter(s) P1-P2'
            if sw2 == 0x00: status += ': no information given'
            elif sw2 == 0x80: status += ': incorrect parameters ' \
                'in the data field'
            elif sw2 == 0x81: status += ': function not supported'
            elif sw2 == 0x82: status += ': file not found'
            elif sw2 == 0x83: status += ': record not found'
            elif sw2 == 0x84: status += ': not enough memory space in the file'
            elif sw2 == 0x85: status += ': Lc inconsistent with TLV structure'
            elif sw2 == 0x86: status += ': incorrect parameters P1-P2'
            elif sw2 == 0x87: status += ': Lc inconsistent with P1-P2'
            elif sw2 == 0x88: status += ': referenced data not found'
            elif sw2 == 0x89: status += ': file already exists'
            elif sw2 == 0x8A: status += ': DF name already exists'
            else: status += ': undefined SW2 code: 0x%s' % toHexString([sw2])
        elif sw1 == 0x6B and sw2 == 0x00: status = 'checking error: '\
            'wrong parameter(s) P1-P2'
        elif sw1 == 0x6C: status = 'checking error: wrong length Le: ' \
            'exact length is %s' % toHexString([sw2])        
        elif sw1 == 0x6D and sw2 == 0x00: status = 'checking error: ' \
            'instruction code not supported or invalid'
        elif sw1 == 0x6E and sw2 == 0x00: status = 'checking error: ' \
            'class not supported'
        elif sw1 == 0x6F and sw2 == 0x00: status = 'checking error: ' \
            'no precise diagnosis'
        return status
    
    def sr_apdu(self, apdu, force=False):
        '''
        sr_apdu(apdu=[0x.., 0x.., ...]) -> 
            list   [ string(apdu sent information),
                     string(SW codes interpretation),
                     2-tuple(sw1, sw2),
                     list(response bytes) ]
                     
        generic function to send apdu, receive and interpret response
        force: force card reconnection if pyscard transmission fails
        '''
        if force:
            try: 
                data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
            except CardConnectionException:
                ISO7816.__init__(self, CLA = self.CLA)
                data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        else:
            data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        # replaces INS code by strings when available
        if apdu[1] in self.INS_dic.keys(): 
            apdu_name =  self.INS_dic[apdu[1]] + ' '
        else: 
            apdu_name = ''
        sw_stat = self.sw_status(sw1, sw2)
        return ['%sapdu: %s' % (apdu_name, toHexString(apdu)),
                'sw1, sw2: %s - %s' % ( toHexString([sw1, sw2]), sw_stat ),
                (sw1, sw2),
                data ]
    
    def bf_cla(self, start=0, param=[0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]):
        '''
        bf_cla( start=int(starting CLA), 
                param=list(bytes for selecting file 0x3F, 0x00) ) ->
            list( CLA which could be supported )
            
        tries all classes CLA codes to check the possibly supported ones
        prints CLA suspected to be supported
        returns the list of those CLA codes
        
        WARNING: 
        can block the card definitively
        Do not do it with your own VISA / MASTERCARD
        '''
        clist = []
        for i in range(start, 256):
            ret = self.sr_apdu([i] + param)
            if ret[2] != (0x6E, 0x00): 
                print ret
                clist.append(i)
        return clist
    
    def bf_ins(self, start=0):
        '''
        bf_cla( start=int(starting INS) ) 
            -> list( INS which could be supported )
            
        tries all instructions INS codes to check the supported ones
        prints INS suspected to be supported
        returns the list of those INS codes
        
        WARNING: 
        can block the card definitively
        Do not do it with your own VISA / MASTERCARD
        '''
        ilist = []
        for i in range(start, 256):
            if self.dbg > 1: 
                print 'DEBUG: testing %d for INS code with %d CLA code' \
                      % (i, self.CLA)
            ret = self.sr_apdu([self.CLA, i, 0x00, 0x00])
            if ret[2] != (0x6D, 0x00): 
                print ret
                ilist.append(i)
        return ilist
    
    ###
    # Below is defined a list of standard commands to be used with (U)SIM cards
    # They are mainly defined and described in 
    # ISO 7816 and described further in ETSI 101.221
    ###
    def READ_BINARY(self, P1=0x00, P2=0x00, Le=0x01):
        '''
        APDU command to read the content of EF file with transparent structure
        Le: length of data bytes to be read
        
        call sr_apdu method
        '''
        READ_BINARY = [self.CLA, 0xB0, P1, P2, Le]
        return self.sr_apdu(READ_BINARY)
    
    def WRITE_BINARY(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to write the content of EF file with transparent structure
        
        Data: list of data bytes to be written
        call sr_apdu method
        '''
        WRITE_BINARY = [self.CLA, 0xD0, P1, P2, len(Data)] + Data
        return self.sr_apdu(WRITE_BINARY)
    
    def UPDATE_BINARY(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to update the content of EF file with transparent structure
        
        Data: list of data bytes to be written
        call sr_apdu method
        '''
        UPDATE_BINARY = [self.CLA, 0xD6, P1, P2, len(Data)] + Data
        return self.sr_apdu(UPDATE_BINARY)
    
    def ERASE_BINARY(self, P1=0x00, P2=0x00, Lc=None, Data=[]):
        '''
        APDU command to erase the content of EF file with transparent structure
        
        Lc: 'None' or '0x02'
        Data: list of data bytes to be written
        call sr_apdu method
        '''
        if Lc is None: 
            ERASE_BINARY = [self.CLA, 0x0E, P1, P2]
        else: 
            ERASE_BINARY = [self.CLA, 0x0E, P1, P2, 0x02] + Data
        return self.sr_apdu(ERASE_BINARY)        
    
    def READ_RECORD(self, P1=0x00, P2=0x00, Le=0x00):
        '''
        APDU command to read the content of EF file with record structure
        
        P1: record number
        P2: reference control
        Le: length of data bytes to be read
        call sr_apdu method
        '''
        READ_RECORD = [self.CLA, 0xB2, P1, P2, Le]
        return self.sr_apdu(READ_RECORD)
    
    def WRITE_RECORD(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to write the content of EF file with record structure
        
        P1: record number
        P2: reference control
        Data: list of data bytes to be written in the record
        call sr_apdu method
        '''
        WRITE_RECORD = [self.CLA, 0xD2, P1, P2, len(Data)] + Data
        return self.sr_apdu(WRITE_RECORD)
    
    def APPEND_RECORD(self, P2=0x00, Data=[]):
        '''
        APDU command to append a record on EF file with record structure
        
        P2: reference control
        Data: list of data bytes to be appended on the record
        call sr_apdu method
        '''
        APPEND_RECORD = [self.CLA, 0xE2, 0x00, P2, len(Data)] + Data
        return self.sr_apdu(APPEND_RECORD)
    
    def UPDATE_RECORD(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to update the content of EF file with record structure
        
        P1: record number
        P2: reference control
        Data: list of data bytes to update the record
        call sr_apdu method
        '''
        APPEND_RECORD = [self.CLA, 0xDC, P1, P2, len(Data)] + Data
        return self.sr_apdu(APPEND_RECORD)
    
    def GET_DATA(self, P1=0x00, P2=0x00, Le=0x01):
        '''
        APDU command to retrieve data object
        
        P1 and P2: reference control for data object description
        Le: number of bytes expected in the response
        call sr_apdu method
        '''
        GET_DATA = [self.CLA, 0xCA, P1, P2, Le]
        return self.sr_apdu(GET_DATA)
    
    def PUT_DATA(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to store data object
        
        P1 and P2: reference control for data object description
        Data: list of data bytes to put in the data object structure
        call sr_apdu method
        '''
        if len(Data) == 0: 
            PUT_DATA = [self.CLA, 0xDA, P1, P2]
        elif 1 <= len(Data) <= 255: 
            PUT_DATA = [self.CLA, 0xDA, P1, P2, len(Data)] + Data
        # should never be the case, however... who wants to try
        else:
            PUT_DATA = [self.CLA, 0xDA, P1, P2, 0xFF] + Data[0:255]
        return self.sr_apdu(PUT_DATA)       
    
    def SELECT_FILE(self, P1=0x00, P2=0x00, Data=[0x3F, 0x00], \
                    with_length=True):
        '''
        APDU command to select file
        
        P1 and P2: selection control
        Data: list of bytes describing the file identifier or address
        call sr_apdu method
        '''
        if with_length:
            Data = [min(len(Data), 255)] + Data
        SELECT_FILE = [self.CLA, 0xA4, P1, P2] + Data
        return self.sr_apdu(SELECT_FILE)
    
    def VERIFY(self, P2=0x00, Data=[]):
        '''
        APDU command to verify user PIN, password or security codes
        
        P2: reference control
        Data: list of bytes to be verified by the card
        call sr_apdu method
        '''
        if len(Data) == 0: 
            VERIFY = [self.CLA, 0x20, 0x00, P2]
        elif 1 <= len(Data) <= 255: 
            VERIFY = [self.CLA, 0x20, 0x00, P2, len(Data)] + Data
        # should never be the case, however... who wants to try
        else: 
            VERIFY = [self.CLA, 0x20, 0x00, P2, 0xFF] + Data[0:255]
        return self.sr_apdu(VERIFY)
    
    def INTERNAL_AUTHENTICATE(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to run internal authentication algorithm
        
        P1 and P2: reference control (algo, secret key selection...)
        Data: list of bytes containing the authentication challenge
        call sr_apdu method
        '''
        INTERNAL_AUTHENTICATE = [self.CLA, 0x88, P1, P2, len(Data)] + Data
        return self.sr_apdu(INTERNAL_AUTHENTICATE)
    
    def EXTERNAL_AUTHENTICATE(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to conditionally update the security status of the card 
        after getting a challenge from it
        
        P1 and P2: reference control (algo, secret key selection...)
        Data: list of bytes containing the challenge response
        call sr_apdu method
        '''
        if len(Data) == 0: 
            EXTERNAL_AUTHENTICATE = [self.CLA, 0x82, P1, P2]
        elif 1 <= len(Data) <= 255: 
            EXTERNAL_AUTHENTICATE = [self.CLA, 0x82, P1, P2, len(Data)] + Data
        # should never be the case, however... who wants to try
        else: 
            EXTERNAL_AUTHENTICATE = [self.CLA, 0x82, P1, P2, 0xFF] + Data[0:255]
        return self.sr_apdu(EXTERNAL_AUTHENTICATE)
    
    def GET_CHALLENGE(self):
        '''
        APDU command to get a challenge for external entity authentication 
        to the card
        
        call sr_apdu method
        '''
        GET_CHALLENGE = [self.CLA, 0x84, 0x00, 0x00]
        return self.sr_apdu(GET_CHALLENGE)
    
    def MANAGE_CHANNEL(self, P1=0x00, P2=0x00):
        '''
        APDU to open and close supplementary logical channels
        
        P1=0x00 to open, 0x80 to close
        P2=0x00, 1, 2 or 3 to ask for logical channel number
        call sr_apdu method
        '''
        if (P1, P2) == (0x00, 0x00): 
            MANAGE_CHANNEL = [self.CLA, 0x70, P1, P2, 0x01]
        else:  
            MANAGE_CHANNEL = [self.CLA, 0x70, P1, P2]
        return self.sr_apdu(MANAGE_CHANNEL)
    
    def GET_RESPONSE(self, Le=0x01):
        '''
        APDU command to retrieve data after selection 
        or other kind of request that should get an extensive reply
        
        Le: expected length of data
        call sr_apdu method
        '''
        GET_RESPONSE = [self.CLA, 0xC0, 0x00, 0x00, Le]
        return self.sr_apdu(GET_RESPONSE)
    
    def ENVELOPPE(self, Data=[]):
        '''
        APDU command to encapsulate data (APDU or other...)
        check ETSI TS 102.221 for some examples...
        
        Data: list of bytes
        call sr_apdu method
        '''
        if len(Data) == 0: 
            ENVELOPPE = [self.CLA, 0xC2, 0x00, 0x00]
        elif 1 <= len(Data) <= 255: 
            ENVELOPPE = [self.CLA, 0xC2, 0x00, 0x00, len(Data)] + Data
        return self.sr_apdu(ENVELOPPE)
    
    def SEARCH_RECORD(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to seach pattern in the current EF file 
        with record structure
        
        P1: record number
        P2: type of search
        Data: list of bytes describing a pattern to search for
        call sr_apdu method
        '''
        SEARCH_RECORD = [self.CLA, 0xA2, P1, P2, len(Data)] + Data
        return self.sr_apdu(SEARCH_RECORD)
    
    def DISABLE_CHV(self, P1=0x00, P2=0x00, Data=[]):
        '''
        APDU command to disable CHV verification (such as PIN or password...)
        
        P1: let to 0x00... or read ISO and ETSI specifications
        P2: type of CHV to disable
        Data: list of bytes for CHV value
        call sr_apdu method
        '''
        DISABLE_CHV = [self.CLA, 0x26, P1, P2, len(Data)] + Data
        return self.sr_apdu(DISABLE_CHV)
    
    def UNBLOCK_CHV(self, P2=0x00, Lc=None, Data=[]):
        '''
        APDU command to unblock CHV code (e.g. with PUK for deblocking PIN)
        
        P2: type of CHV to unblock
        Lc: Empty or 0x10
        Data: if Lc=0x10, UNBLOCK_CHV value and new CHV value to set
        call sr_apdu method
        
        TODO: check the exact coding for the Data
        '''
        if Lc is None: 
            UNBLOCK_CHV = [self.CLA, 0x2C, 0x00, P2]
        else: 
            UNBLOCK_CHV = [self.CLA, 0x2C, 0x00, P2, 0x10] + Data
        return self.sr_apdu(UNBLOCK_CHV) 
    
    ##########################
    # evolved "macro" method for ISO7816 card
    # need the "coms" attribute being an apdu_stack()
    ##########################
    def parse_file(self, Data=[]):
        '''
        parse_file(self, Data) -> Dict()
        
        parses a list of bytes returned when selecting a file
        interprets the content of some informative bytes 
        for file structure and parsing method...
        '''
        ber = BERTLV_parser( Data )
        if self.dbg > 1:
            print '[DBG] BER structure:\n%s' % ber
        if len(ber) > 1:
            # TODO: implements recursive BER object parsing
            print '[WNG] more than 1 BER object: %s' % ber
        
        # for FCP control structure, precise parsing is done
        # this structure seems to be the most used for (U)SIM cards
        if ber[0][0][2] == 0x2: 
            fil = self.parse_FCP( ber[0][2] )
            fil['Control'] = 'FCP'
            return fil
        
        # for other control structure, DIY
        fil = {}
        if ber[0][0][2] == 0x4: 
            fil['Control'] = 'FMD'
            if self.dbg:
                print '[WNG] FMD file structure parsing not implemented'
        elif ber[0][0][2] == 0xF: 
            fil['Control'] = 'FCI'
            if self.dbg:
                print '[WNG] FCI file structure parsing not implemented'
        else: 
            fil['Control'] = ber[0][0]
            if self.dbg:
                print '[WNG] unknown file structure'
        fil['Data'] = ber[0][2]
        
        return fil
    
    def parse_FCP(self, Data=[]):
        '''
        parse_FCP(Data) -> Dict()
        
        parses a list of bytes returned when selecting a file
        interprets the content of some informative bytes 
        for file structure and parsing method...
        '''
        fil = {}
        # loop on the Data bytes to parse TLV'style attributes
        toProcess = Data
        while len(toProcess) > 0:
            # TODO: seemd full compliancy 
            # would require to work with the BERTLV parser...
            [T, L, V] = first_TLV_parser(toProcess)
            if self.dbg > 2:
                if T in self.file_tags.keys(): 
                    Tag = self.file_tags[T]
                else: 
                    Tag = T
                print '[DBG] %s / %s: %s' % (T, Tag, V)
            
            # do extra processing here
            # File ID, DF name, Short file id
            if T in (0x83, 0x84, 0x88):
                fil[self.file_tags[T]] = V
            # Security Attributes compact format
            elif T == 0x8C:
                fil[self.file_tags[T]] = V
                fil = self.parse_security_attribute_compact(V, fil)
            # Security Attributes
            elif T in (0x86, 0x8B, 0x8E, 0xA0, 0xA1, 0xAB):
                fil[self.file_tags[T]] = V 
                # TODO: no concrete parsing at this time... 
                fil = self.parse_security_attribute(V, fil)
            # file size or length
            elif T in (0x80, 0x81):
                fil[self.file_tags[T]] = sum( [ V[i] * pow(0x100, len(V)-i-1) \
                                               for i in range(len(V)) ] )
            # file descriptor, deducting file access, type and structure
            elif T == 0x82:
                assert( L in (2, 5) )
                fil[self.file_tags[T]] = V
                fil = self.parse_file_descriptor(V, fil)
            # life cycle status
            elif T == 0x8A:
                fil = self.parse_life_cycle(V, fil)
            # proprietary information
            elif T == 0xA5:
                fil = self.parse_proprietary(V, fil)
            else:
                if T in self.file_tags.keys():
                    fil[self.file_tags[T]] = V
                else:
                    fil[T] = V
            
            # truncate the data to process and loop
            if L < 256:
                toProcess = toProcess[L+2:]
            else:
                toProcess = toProcess[L+4:]
        
        # and return the file 
        return fil
    
    @staticmethod
    def parse_life_cycle(Data, fil):
        '''
        parses a list of bytes provided in Data
        interprets the content as the life cycle
        and enriches the file dictionnary passed as argument
        '''
        if   Data[0] == 1: fil['Life Cycle Status'] = 'creation state'
        elif Data[0] == 3: fil['Life Cycle Status'] = 'initialization state'
        elif Data[0] in (5, 7): fil['Life Cycle Status'] = 'operational state' \
            ' - activated'
        elif Data[0] in (4, 6): fil['Life Cycle Status'] = 'operational state' \
            ' - deactivated'
        elif Data[0] in range(12, 15): fil['Life Cycle Status'] = \
            'termination state'
        elif Data[0] >= 16: fil['Life Cycle Status'] = 'proprietary'
        else: fil['Life Cycle Status'] = 'RFU'
        return fil
    
    @staticmethod
    def parse_file_descriptor(Data, fil):
        '''
        parses a list of bytes provided in Data
        interprets the content as the file descriptor
        and enriches the file dictionnary passed as argument
        '''
        # parse the File Descriptor Byte
        fd = Data[0]
        fd_type = (fd >> 3) & 0b00111
        fd_struct = fd & 0b00000111
        # get Structure, Access and Type
        # bit b8
        if (fd >> 7) & 0b1: fil['Structure'] = 'RFU'
        # access bit b7
        if (fd >> 6) & 0b1: fil['Access'] = 'shareable'
        else              : fil['Access'] = 'not shareable'
        # structure bits b1 to b3
        if   fd_struct == 0: fil['Structure'] = 'no information'
        elif fd_struct == 1: fil['Structure'] = 'transparent'
        elif fd_struct == 2: fil['Structure'] = 'linear fixed'
        elif fd_struct == 3: fil['Structure'] = 'linear fixed TLV'
        elif fd_struct == 4: fil['Structure'] = 'linear variable'
        elif fd_struct == 5: fil['Structure'] = 'linear variable TLV'
        elif fd_struct == 6: fil['Structure'] = 'cyclic'
        elif fd_struct == 7: fil['Structure'] = 'cyclic TLV'
        else               : fil['Structure'] = 'RFU'
        # type bits b4 to b6
        if   fd_type == 0: fil['Type'] = 'EF working'
        elif fd_type == 1: fil['Type'] = 'EF internal'
        elif fd_type == 7: 
            fil['Type'] = 'DF'
            if   fd_struct == 1: fil['Structure'] = 'BER-TLV'
            elif fd_struct == 2: fil['Structure'] = 'TLV'
        else: fil['Type'] = 'EF proprietary'
        
        # for linear and cyclic EF: 
        # the following is convenient for UICC, 
        # but looks not fully conform to ISO standard
        # see coding convention in ISO 7816-4 Table 87
        if len(Data) == 5: 
            fil['Record Length'], fil['Record Number'] = Data[3], Data[4]
        
        return fil
    
    @staticmethod
    def parse_proprietary(Data, fil):
        '''
        parses a list of bytes provided in Data
        interprets the content as the proprietary parameters
        and enriches the file dictionnary passed as argument
        '''
        propr_tags = {
            0x80:"UICC characteristics",
            0x81:"Application power consumption",
            0x82:"Minimum application clock frequency",
            0x83:"Amount of available memory",
            0x84:"File details",
            0x85:"Reserved file size",
            0x86:"Maximum file size",
            0x87:"Supported system commands",
            0x88:"Specific UICC environmental conditions",
            }
        while len(Data) > 0:
            [T, L, V] = first_TLV_parser( Data )
            if T in propr_tags.keys(): 
                fil[propr_tags[T]] = V
            Data = Data[L+2:]
        return fil
    
    @staticmethod
    def parse_security_attribute_compact(Data, fil):
        '''
        parses a list of bytes provided in Data
        interprets the content as the compact form for security parameters
        and enriches the file dictionnary passed as argument
        '''
        # See ISO-IEC 7816-4 section 5.4.3, with compact and expanded format
        AM = Data[0]
        SC = Data[1:]
        sec = '#'
        
        if 'Type' in fil.keys():
            # DF parsing
            if fil['Type'] == 'DF':
                if AM & 0b10000000 == 0:
                    if AM & 0b01000000: sec += ' DELETE FILE #'
                    if AM & 0b00100000: sec += ' TERMINATE DF #'
                    if AM & 0b00010000: sec += ' ACTIVATE FILE #'
                    if AM & 0b00001000: sec += ' DEACTIVATE FILE #'
                if AM & 0b00000100: sec += ' CREATE DF #'
                if AM & 0b00000010: sec += ' CREATE EF #'
                if AM & 0b00000001: sec += ' DELETE FILE #'
            # EF parsing
            else:
                if AM & 0b10000000 == 0:
                    if AM & 0b01000000: sec += ' DELETE FILE #'
                    if AM & 0b00100000: sec += ' TERMINATE EF #'
                    if AM & 0b00010000: sec += ' ACTIVATE FILE #'
                    if AM & 0b00001000: sec += ' DEACTIVATE FILE #'
                if AM & 0b00000100: sec += ' WRITE / APPEND #'
                if AM & 0b00000010: sec += ' UPDATE / ERASE #'
                if AM & 0b00000001: sec += ' READ / SEARCH #'
        
            # loop on SC:
            for cond in SC:
                if   cond == 0   : sec += ' Always #'
                elif cond == 0xff: sec += ' Never #'
                else:
                    sec += ' SEID %s #' % (cond & 0b00001111)
                    if cond & 0b10000000: sec += ' all conditions #'
                    else: sec += ' at least 1 condition #'
                    if cond & 0b01000000: sec += ' secure messaging #'
                    if cond & 0b00100000: sec += ' external authentication #'
                    if cond & 0b00010000: sec += ' user authentication #'
            
            #file['Security Attributes raw'] = Data
            fil['Security Attributes'] = sec
        return fil
    
    @staticmethod
    def parse_security_attribute(Data, fil):
        '''
        TODO: to implement...
        
        need to work further on how to do it (with ref to EF_ARR)
        '''
        # See ISO-IEC 7816-4 section 5.4.3, with compact and expanded format
        #if self.dbg:
        #    print '[DBG] parse_security_attribute() not implemented'
        return fil
        
    def read_EF(self, fil):
        '''
        interprets the content of file parameters (Structure, Size, Length...)
        and enriches the file dictionnary passed as argument
        with "Data" key and corresponding 
        - list of bytes for EF transparent
        - list of list of bytes for cyclic or linear EF
        '''
        # read EF transparent data
        if fil['Structure'] == 'transparent':
            self.coms.push( self.READ_BINARY(Le=fil['Size']) )
            if self.coms()[2] != (0x90, 0x00):
                if self.dbg > 1: 
                    print '[DBG] %s' % self.coms()
                return fil
            fil['Data'] = self.coms()[3]
        
        # read EF cyclic / linear all records data
        elif fil['Structure'] != 'transparent':
            fil['Data'] = []
            # for record data: need to check the number of recordings
            # stored in the file, and iterate for each
            for i in range( (fil['Size'] / fil['Record Length']) ):
                self.coms.push( self.READ_RECORD(P1=i+1, P2=0x04, \
                    Le=fil['Record Length']) )
                if self.coms()[2] != (0x90, 0x00):
                    # should mean there is an issue 
                    # somewhere in the file parsing process
                    if self.dbg:
                        print '[WNG] error in iterating the RECORD parsing at' \
                              ' iteration %s\n%s' % (i, self.coms())
                    return fil
                if self.coms()[3][1:] == len(self.coms()[3][1:]) * [255]:
                    # record is empty, contains padding only
                    pass
                else: 
                    fil['Data'].append(self.coms()[3])
        
        # return the [Data] for transparent or 
        # [[Record1],[Record2]...] for cyclic / linear
        return fil
    
    def select(self, Data=[0x3F, 0x00], typ="fid", with_length=True):
        '''
        self.select(Data=[0x.., 0x..], typ="fid", with_length=True) 
            -> dict(file) on success, None on error
        
        selects the file
        if error, returns None
        if processing correct: gets response with info on the file
        if processing correct and EF file: reads the data in the file
            works in USIM fashion
        else returns the data dictionnary: check parse_file_(U)SIM methods
        last apdu available from the attribute self.coms
        
        different types of file selection are possible:
        "fid": select by file id, only the direct child or 
               parent files of the last selected MF / DF / ADF
        "pmf": select by path from MF
        "pdf": select by path from last selected MF / DF / ADF 
               (or relative path)
        "aid": select by ADF (Application) name
        '''
        # get the UICC trigger
        is_UICC = isinstance(self, UICC)
        
        # handle type of selection:
        if   typ == "pmf": P1 = 0x08
        elif typ == "pdf": P1 = 0x09
        elif typ == "aid": P1 = 0x04
        # the case of selection by "fid":
        else: P1 = 0x00 
        
        # for UICC instance
        # ask the return of the FCP template for the selected file:
        if is_UICC:
            P2 = 0x04
        else:
            P2 = 0x00
        
        # used to get back to MF without getting MF attributes:
        if len(Data) == 0: 
            P1, P2 = 0x00, 0x0C
        
        # select file and check SW; if error, returns None, 
        # else get response
        self.coms.push(self.SELECT_FILE(P1=P1, P2=P2, Data=Data, \
            with_length=with_length))
        
        # different SW codes for UICC and old ISO card (e.g. SIM)
        if is_UICC and self.coms()[2][0] != 0x61 \
        or not is_UICC and self.coms()[2][0] != 0x9F:
            if self.dbg > 1: 
                print '[DBG] %s' % self.coms()
            return None
            
        # get response and check SW: 
        # if error, return None, else parse file info
        self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
        if self.coms()[2] != (0x90, 0x00):
            if self.dbg > 1: 
                print '[DBG] %s' % self.coms()
            return None
        
        data = self.coms()[3]
        # take the `parse_file()' method from the instance:
        # ISO7816, UICC or SIM
        fil = self.parse_file(data)
        if fil['Type'][0:2] == 'EF':
            fil = self.read_EF(fil)
        
        # finally returns the whole file dictionnary, 
        # containing the ['Data'] key for EF file
        return fil
    
    ###############
    # The following may need some improvements
    ###############
    
    def flat_files_bf(self, path=[], under_AID=0, \
                      hi_addr=(0, 0xff), lo_addr=(0, 0xff)):
        '''
        flat_files_bf(self, path=[], under_AID=0, \
                      hi_addr=(0, 0xff), lo_addr=(0, 0xff))
            -> list(files), list(DF_to_explore)
        
        path: path of the DF under MF or AID to brute force
        under_AID: if > 0, select the AID number to init the brute force
            only available for UICC instance
        hi_addr: 8 MSB of the file address to brute force
        lo_addr: 8 LSB of the file address to brute force
        
        brute force file addresses of direct child under a given DF
        get information on existing files, and discovered DF
        '''
        # init return variables
        FS, DF_to_explore = [], []
        # init selection process
        MF, sel_type = [0x3F, 0x00], 'fid'
        if isinstance(self, UICC):
            sel_type = 'pdf'
        
        # start by selecting MF
        try:
            r = self.select(MF)
        except:
            print '[ERR] selecting MF failed'
            return
        if r == None:
            print '[ERR] MF not found!'
            return
        
        #if needed, select AID
        if isinstance(self, UICC) and under_AID:
            try:
                self.get_AID()
                r = self.select_by_aid(under_AID)
            except:
                print '[ERR] selecting AID failed'
                return
            if r == None:
                print '[ERR] AID not found'
                return
        
        # place on the DF path to bf
        # select it according to the card application selection type
        under_df = None
        if len(path) > 0:
            try:
                path_init = self.select(path, sel_type)
                under_df = path[-2:]
            except:
                print '[ERR] selecting path failed:\n%s' % self.coms()
                return
            if path_init == None:
                print '[ERR] path not found: %s' % path
                return
        
        # Dany'style programming
        def reinit():
            self.select(MF)
            if isinstance(self, UICC) and under_AID:
                self.select_by_aid(under_AID)
            if len(path) > 0:
                self.select(path, sel_type)
        
        # loop over the address space to brute force files
        i, j = 0, 0
        for i in range(hi_addr[0], hi_addr[1]+1):
            if self.dbg and i%2 == 0:
                print '[DBG] addr: %s %s %s' % ([hex(v) for v in path], \
                       hex(i), hex(j))
            for j in range(lo_addr[0], lo_addr[1]+1):
                # avoid MF re-selection:
                if [i, j] == MF:
                    fil = None
                    if self.dbg:
                    	print '[] avoid looping reselecting MF'
                # avoid DF self reselection:
                elif under_df and [i, j] == under_df:
                    fil = None
                    if self.dbg:
                        print '[] avoid looping reselecting current DF'
                # select by direct file id
                else:
                    fil = self.select([i, j], sel_type)
                    if fil:
                        if self.dbg:
                            print '[DBG] found file at path, id: ' \
                                  '%s %s' % (path, [i, j])
                        if 'File Identifier' in fil.keys():
                            fil['Absolut Path'] = path+fil['File Identifier']
                        FS.append(fil)
                        if 'Type' in fil.keys() and fil['Type'] == 'DF':
                            reinit()
                            if 'Absolut Path' in fil.keys():
                                DF_to_explore.append(fil['Absolut Path'])
        
        # re-initialize at MF and return
        self.select(MF)
        return FS, DF_to_explore
    
    def recu_files_bf(self, path=[], under_AID=0):
        '''
        recu_files_bf(self, path=[], under_AID=0)
            -> void
        
        fills self.FS attribute with all files and DF discovered
        recursively
        '''
        #TODO: put a maximum recursion parameter
        
        # list all files and DF on the path
        ret = self.flat_files_bf(path=path, under_AID=under_AID)
        try:
            self.FS += ret[0]
        except:
            '[ERR] FS not initialized: %s' % type(self.FS)
            return
        DF = ret[1]
        
        # this should never happen:
        for addr in DF:
            if 0x3f in addr and 0x00 == addr[addr.index(0x3f)+1]:
                print 'looks like its going to loop infinitely...'
                
        # recursive method call
        # DF contains absolut path
        for addr in DF:
            print '[DBG] path: %s' % addr
            self.recu_files_bf(path=addr, under_AID=under_AID)
    
    def init_FS(self):
        self.FS = []
    

##############################################
# UICC is defined in ETSI 102.221 mainly, 
# and used for many telco applications
##############################################

class UICC(ISO7816):
    '''
    define attributes, methods and facilities for ETSI UICC card
    check UICC specifications mainly in ETSI TS 102.221
    
    inherits (eventually overrides) methods and objects from ISO7816 class
    use self.dbg = 1 or more to print live debugging information
    '''
    AID_RID = {
        (0xA0, 0x00, 0x00, 0x00, 0x09): 'ETSI',
        (0xA0, 0x00, 0x00, 0x00, 0x87): '3GPP',
        (0xA0, 0x00, 0x00, 0x03, 0x43): '3GPP2',
        (0xA0, 0x00, 0x00, 0x04, 0x12): 'OMA',
        (0xA0, 0x00, 0x00, 0x04, 0x24): 'WiMAX',
        }
    ETSI_AID_app_code = {
        (0x00, 0x00): 'Reserved',
        (0x00, 0x01): 'GSM',
        (0x00, 0x02): 'GSM SIM Toolkit',
        (0x00, 0x03): 'GSM SIM API for JavaCard',
        (0x00, 0x04): 'Tetra',
        (0x00, 0x05): 'UICC API for JavaCard',
        (0x01, 0x01): 'DVB CBMS KMS',
        }
    GPP_AID_app_code = {
        (0x10, 0x01): 'UICC',
        (0x10, 0x02): 'USIM',
        (0x10, 0x03): 'USIM Toolkit',
        (0x10, 0x04): 'ISIM',
        (0x10, 0x05): 'USIM API for JavaCard',
        (0x10, 0x06): 'ISIM API for JavaCard',
        (0x10, 0x05): 'Contact Manager API for JavaCard',
        }
    GPP2_AID_app_code = {
        (0x10, 0x02): 'CSIM',
        }
    AID_country_code = {
        (0xFF, 0x33): 'France',
        (0xFF, 0x44): 'United Kingdom',
        (0xFF, 0x49): 'Germany',
        }
    
    pin_status = {
        0x01 : "PIN Appl 1",
        0x02 : "PIN Appl 2",
        0x03 : "PIN Appl 3",
        0x04 : "PIN Appl 4",
        0x05 : "PIN Appl 5",
        0x06 : "PIN Appl 6",
        0x07 : "PIN Appl 7",
        0x08 : "PIN Appl 8",
        0x09 : "RFU",
        0x0A : "ADM1",
        0x0B : "ADM2",
        0x0C : "ADM3",
        0x0D : "ADM4",
        0x0E : "ADM5",
        0x11 : "PIN Universal PIN",
        0x81 : "Second PIN Appl 1",
        0x82 : "Second PIN Appl 2",
        0x83 : "Second PIN Appl 3",
        0x84 : "Second PIN Appl 4",
        0x85 : "Second PIN Appl 5",
        0x86 : "Second PIN Appl 6",
        0x87 : "Second PIN Appl 7",
        0x88 : "Second PIN Appl 8",
        0x89 : "RFU",
        0x8A : "ADM6",
        0x8B : "ADM7",
        0x8C : "ADM8",
        0x8D : "ADM9",
        0x8E : "ADM10",
        }
    
    files = [
        ([0x3F, 0x00], 'MF', 'MF'),
        ([0x2F, 0x00], 'EF', 'EF_DIR'),
        ([0x2F, 0x01], 'EF', 'EF_ATR'),
        ([0x2F, 0x05], 'EF', 'EF_PL'),
        ([0x2F, 0x06], 'EF', 'EF_ARR'),
        ([0x2F, 0x2E], 'EF', 'EF_ICCID'),
        ([0x7F, 0xFF], 'DF', 'current ADF'),
        ([0x7F, 0x10], 'DF', 'DF_TELECOM'),
        ([0x7F, 0x10, 0x5F, 0x50], 'DF', 'DF_GRAPHICS'),
        ([0x7F, 0x10, 0x5F, 0x3A], 'DF', 'DF_PHONEBOOK'),
        ([0x7F, 0x20], 'DF', 'DF_GSM'),
        ([0x7F, 0x21], 'DF', 'DF_DCS1800'),
        ([0x7F, 0x22], 'DF', 'DF_IS-41'),
        ([0x7F, 0x23], 'DF', 'DF_FP-CTS'),
        ([0x7F, 0x24], 'DF', 'DF_TIA-EIA136'),
        ([0x7F, 0x25], 'DF', 'DF_TIA-EIA95'),
        ([0x7F, 0x80], 'DF', 'DF_PDC'),
        ([0x7F, 0x90], 'DF', 'DF_TETRA'),
        ([0x7F, 0x31], 'DF', 'DF_iDEN'),
        ]
    
    def __init__(self):
        '''
        initializes like an ISO7816-4 card with CLA=0x00
        and check available AID (Application ID) read from EF_DIR
        
        initializes on the MF
        '''
        ISO7816.__init__(self, CLA=0x00)
        self.AID = []
        
        if self.dbg:
            print '[DBG] type definition: %s' % type(self)
            print '[DBG] CLA definition: %s' % hex(self.CLA)
            #print '[DBG] EF_DIR file selection and reading...'
    
    def parse_file(self, Data=[]):
        '''
        parse_file(Data=[0x12, 0x34, 0x56, 0x89]) -> dict(file)
        mainly based on the ISO7816 parsing style
        
        parses a list of bytes returned when selecting a file
        interprets the content of some informative bytes for right accesses, 
        type / format of file... see TS 102.221
        works over the UICC file structure (quite different from e.g. SIM card)
        '''
        # First ISO7816 parsing
        fil = ISO7816.parse_file(self, Data)
        
        # Then UICC extra attributes parsing
        if 0xC6 in fil.keys():
            fil = self.parse_pin_status(fil[0xC6], fil)
            del fil[0xC6]
        
        if 'File Identifier' in fil.keys():
            for ref in self.files:
                if fil['File Identifier'] == ref[0]:
                    fil['Name'] = ref[2]
        
        # return the enriched file 
        return fil
    
    @staticmethod
    def parse_pin_status(Data, fil):
        '''
        parses a list of bytes provided in Data
        interprets the content as the UICC pin status
        and enriches the file dictionnary passed as argument
        '''
        PS_DO = Data[2:2+Data[1]]
        Data = Data[2+len(PS_DO):]
        PIN_status = ''
        while len(Data) > 0:
            [T, L, V] = first_TLV_parser(Data)
            assert( T in (0x83, 0x95) )
            if T == 0x95: # PIN usage
                if (V[0] << 7) & 1: 
                    PIN_status += '#use verification / encipherment ' \
                                  '/ external authentication: '
                elif (V[0] << 6) & 1: 
                    PIN_status += '#use computation / decipherment ' \
                                  '/ internal authentication: '
                elif (V[0] << 5) & 1: 
                    PIN_status += '#use SM response: '
                elif (V[0] << 4) & 1: 
                    PIN_status += '#use SM command: '
                elif (V[0] << 3) & 1: 
                    PIN_status += '#use PIN verification: '
                elif (V[0] << 3) & 1: 
                    PIN_status += '#use biometric user verification: '
                elif  V[0] == 0: 
                    PIN_status += '#verification not required: '
            elif T == 0x83: # PIN status
                if len(PIN_status) == 0: PIN_status = '#'
                if 0x00 <  V[0] < 0x12 or   0x81 <= V[0] < 0x90: 
                    PIN_status += UICC.pin_status[V[0]] + '#'
                elif 0x12 <= V[0] < 0x1E:
                    PIN_status += 'RFU (Global)#'
                elif 0x90 <= V[0] < 0x9F:
                    PIN_status += 'RFU (Local)#'
                else: 
                    PIN_status += '#'
            #if self.dbg >= 2: 
            #    print '[DBG] %s: %s; PIN status: %s' % (T, V, PIN_status)
            Data = Data[L+2:]
        fil['PIN Status'] = PIN_status
        return fil
    
    def get_AID(self):
        '''
        checks EF_DIR at the MF level, 
        and available AID (Application ID) referenced
        
        puts it into self.AID
        interprets and print the content of the self.AID list
        '''
        #go back to MF and select EF_DIR
        #self.select(Data=[])
        
        # EF_DIR is at the MF level and contains Application ID:
        EF_DIR = self.select([0x2F, 0x00], typ='pmf')
        if self.dbg: 
            print '[DBG] EF_DIR: %s' % EF_DIR
        if EF_DIR is None: 
            return None
        
        # EF_DIR is an EF with linear fixed structure: contains records:
        for rec in EF_DIR['Data']:
            # check for a (new) AID:
            if (rec[0], rec[2]) == (0x61, 0x4F) and len(rec) > 6 \
            and rec[4:4+rec[3]] not in self.AID:
                self.AID.append( rec[4:4+rec[3]] )
        
        i = 1
        for aid in self.AID:
            aid_rid = tuple(aid[0:5])
            aid_app = tuple(aid[5:7])
            aid_country = tuple(aid[7:9])
            aid_provider = tuple(aid[9:11])
            
            # get AID application code, depending on SDO...
            if aid_rid == (0xA0, 0x00, 0x00, 0x00, 0x09) \
            and aid_app in self.ETSI_AID_app_code.keys(): 
                aid_app = self.ETSI_AID_app_code[aid_app]
            if aid_rid == (0xA0, 0x00, 0x00, 0x00, 0x87) \
            and aid_app in self.GPP_AID_app_code.keys(): 
                aid_app = self.GPP_AID_app_code[aid_app]
            if aid_rid == (0xA0, 0x00, 0x00, 0x03, 0x43) \
            and aid_app in self.GPP2_AID_app_code.keys(): 
                aid_app = self.GPP2_AID_app_code[aid_app]
            # get AID responsible SDO and country
            if aid_rid in self.AID_RID.keys(): aid_rid = self.AID_RID[aid_rid]
            if aid_country in self.AID_country_code.keys(): 
                aid_country = self.AID_country_code[aid_country]
            
            print 'found [AID %s] %s || %s || %s || %s || %s' \
                  % (i, aid_rid, aid_app, aid_country, \
                     aid_provider, tuple(aid[11:]) )
            i += 1
    
    def get_ICCID(self):
        '''
        check EF_ICCID at the MF level, 
        and returnq the ASCII value of the ICCID        
        '''
        #go back to MF and select EF_ICCID
        #self.select(Data=[])
        
        # EF_ICCID is at the MF level and contains Application ID:
        EF_ICCID = self.select([0x2F, 0xE2], typ='pmf')
        if self.dbg: 
            print '[DBG] EF_ICCID: %s' % EF_ICCID
        if EF_ICCID is None: 
            return None
        return decode_BCD( EF_ICCID['Data'] )
    
    def select_by_name(self, name=''):
        '''
        AID selection by name taken from UICC.files
        '''
        for i in range(len(self.files)):
            if name == self.files[i][2]:
                return self.select( self.files[i][0], 'pmf' )
    
    def select_by_aid(self, aid_num=1):
        '''
        AID selection by index
        '''
        if len(self.AID) != 0:
            return self.select(self.AID[aid_num-1], 'aid')
    


