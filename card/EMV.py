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
############################################
# Python library to work on EMV cards      #
# communication based on ISO7816 card      #
#                                          #
# needs pyscard from:                      #
# http://pyscard.sourceforge.net/          #
#                                          #
# EMV standards available at:              #
# http://www.emvco.com/specifications.aspx #
############################################

from card.ICC import ISO7816
from card.utils import *


class EMV(ISO7816):
    dbg = 2
    
    # AID RID & PIX codes taken from wikipedia
    AID_RID = {
        (0xA0, 0x00, 0x00, 0x00, 0x03): 'Visa',
        (0xA0, 0x00, 0x00, 0x00, 0x04): 'MasterCard',
        (0xA0, 0x00, 0x00, 0x00, 0x05): 'MasterCard',
        (0xA0, 0x00, 0x00, 0x00, 0x25): 'American Express',
        (0xA0, 0x00, 0x00, 0x00, 0x29): 'LINK ATM (UK)',
        (0xA0, 0x00, 0x00, 0x00, 0x42): 'CB (FR)',
        (0xA0, 0x00, 0x00, 0x00, 0x65): 'JCB (JP)',
        (0xA0, 0x00, 0x00, 0x01, 0x21): 'Dankort (DN)',
        (0xA0, 0x00, 0x00, 0x01, 0x41): 'CoGeBan (IT)',
        (0xA0, 0x00, 0x00, 0x01, 0x52): 'Diners Club', # 'Discover'
        (0xA0, 0x00, 0x00, 0x01, 0x54): 'Banrisul (BR)',
        (0xA0, 0x00, 0x00, 0x02, 0x28): 'SPAN2 (SA)',
        (0xA0, 0x00, 0x00, 0x02, 0x77): 'Interac (CA)',
        (0xA0, 0x00, 0x00, 0x03, 0x33): 'China UnionPay',
        (0xA0, 0x00, 0x00, 0x03, 0x59): 'ZKA (DE)',
        }
    
    AID_Visa_PIX = {
        (0x10, 0x10): 'credit or debit',
        (0x20, 0x10): 'Electron',
        (0x20, 0x20): 'V Pay',
        (0x80, 0x10): 'Plus',
        }
    
    AID_MasterCard_PIX = {
        (0x10, 0x10): 'credit or debit',
        (0x99, 0x99): 'paypass',
        (0x30, 0x60): 'Maestro',
        (0x60, 0x00): 'Cirrus',
        }
    
    AID_ChinaUnionPay_PIX = {
        (0x01, 0x01, 0x01): 'debit',
        (0x01, 0x01, 0x02): 'credit',
        (0x01, 0x01, 0x03): 'quasi credit',
        }
    
    
    def __init__(self):
        '''
        initializes like an ISO7816-4 card with CLA=0x00
        and check available AID (Application ID) read straight after card init
        '''
        ISO7816.__init__(self, CLA=0x00)
        self.AID = []
        
        if self.dbg >= 2:
            log(3, '(UICC.__init__) type definition: %s' % type(self))
            log(3, '(UICC.__init__) CLA definition: %s' % hex(self.CLA))
    
    
    def get_AID(self):
        '''
        checks AID straight after card init, 
        and read available AID (Application ID) referenced
        
        puts it into self.AID
        '''
        # read record to get EMV Application DF supported by the ICC
        recs = []
        SFI = 1 # I dont know exactly why... but it works, at least
        index = 1
        while True:
            ret = self.READ_RECORD(P1=index, P2=(SFI<<3)|4)
            index += 1
            if ret[2] == (0x90, 0x0):
                recs.append(ret[3])
            else:
                break
        #
        for rec in recs:
            # try to interpret EMV AID
            if (rec[0], rec[2]) == (0x70, 0x61) and len(rec) >= 11 \
            and rec[6:6+rec[5]] not in self.AID:
                self.AID.append( rec[6:6+rec[5]] )
            if self.dbg:
                log(3, '(EMV.__init__) AID found: %s' % EMV.interpret_AID(self.AID[-1]))
    
    @staticmethod
    def interpret_AID(aid=[]):
        aid = tuple(aid)
        inter = ''
        if aid[:5] in self.AID_RID:
            inter = self.AID_RID[aid[:5]]
            if aid[:5] == (0xA0, 0x00, 0x00, 0x00, 0x03):
                inter += ' - %s' % self.AID_Visa_PIX
            elif aid[:5] in ((0xA0, 0x00, 0x00, 0x00, 0x04), \
                             (0xA0, 0x00, 0x00, 0x00, 0x05)):
                inter += ' - %s' % self.AID_MasterCard_PIX
            elif aid[:5] in (0xA0, 0x00, 0x00, 0x03, 0x33):
                inter += ' - %s' % self.AID_ChinaUnionPay_PIX
        else:
            inter = 'unkown EMV AID'
        #
        return inter

