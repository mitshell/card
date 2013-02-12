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
# SIM card
# communication based on ISO7816 card
#
# needs pyscard from:
# http://pyscard.sourceforge.net/
#################################

from card.ICC import ISO7816
from card.FS import SIM_FS, MF_FS
from card.utils import *

SIM_service_table = {
    1 : "CHV1 disable function",
    2 : "Abbreviated Dialling Numbers (ADN)",
    3  : "Fixed Dialling Numbers (FDN)",
    4  : "Short Message Storage (SMS)",
    5  : "Advice of Charge (AoC)",
    6  : "Capability Configuration Parameters (CCP)",
    7  : "PLMN selector",
    8  : "RFU",
    9  : "MSISDN",
    10 : "Extension1",
    11 : "Extension2",
    12 : "SMS Parameters",
    13 : "Last Number Dialled (LND)",
    14 : "Cell Broadcast Message Identifier",
    15 : "Group Identifier Level 1",
    16 : "Group Identifier Level 2",
    17 : "Service Provider Name",
    18 : "Service Dialling Numbers (SDN)",
    19 : "Extension3",
    20 : "RFU",
    21 : "VGCS Group Identifier List (EFVGCS and EFVGCSS)",
    22 : "VBS Group Identifier List (EFVBS and EFVBSS)",
    23 : "enhanced Multi-Level Precedence and Pre-emption Service",
    24 : "Automatic Answer for eMLPP",
    25 : "Data download via SMS-CB",
    26 : "Data download via SMS-PP",
    27 : "Menu selection",
    28 : "Call control",
    29 : "Proactive SIM",
    30 : "Cell Broadcast Message Identifier Ranges",
    31 : "Barred Dialling Numbers (BDN)",
    32 : "Extension4",
    33 : "De-personalization Control Keys",
    34 : "Co-operative Network List",
    35 : "Short Message Status Reports",
    36 : "Network's indication of alerting in the MS ",
    37 : "Mobile Originated Short Message control by SIM ",
    38 : "GPRS",
    39 : "Image (IMG)",
    40 : "SoLSA (Support of Local Service Area)",
    41 : "USSD string data object supported in Call Control",
    42 : "RUN AT COMMAND command",
    43 : "User controlled PLMN Selector with Access Technology",
    44 : "Operator controlled PLMN Selector with Access Technology",
    45 : "HPLMN Selector with Access Technology",
    46 : "CPBCCH Information",
    47 : "Investigation Scan",
    48 : "Extended Capability Configuration Parameters",
    49 : "MExE",
    50 : "RPLMN last used Access Technology",
    51 : "PLMN Network Name",
    52 : "Operator PLMN List",
    53 : "Mailbox Dialling Numbers ",
    54 : "Message Waiting Indication Status",
    55 : "Call Forwarding Indication Status",
    56 : "Service Provider Display Information",
    }

class SIM(ISO7816):
    '''
    define attributes, methods and facilities for ETSI / 3GPP SIM card
    check SIM specifications in ETSI TS 102.221 and 3GPP TS 51.011
    
    inherit methods and objects from ISO7816 class
    use self.dbg = 1 or more to print live debugging information
    '''
    
    def __init__(self):
        '''
        initialize like an ISO7816-4 card with CLA=0xA0
        can also be used for USIM working in SIM mode,
        '''
        ISO7816.__init__(self, CLA=0xA0)
        
        if self.dbg >= 2:
            log(3, '(SIM.__init__) type definition: %s' % type(self))
            log(3, '(SIM.__init__) CLA definition: %s' % hex(self.CLA))
        
    @staticmethod
    def sw_status(sw1, sw2):
        '''
        sw_status(sw1=int, sw2=int) -> string
        
        extends SW status bytes interpretation from ISO7816 
        with ETSI / 3GPP SW codes
        helps to speak with the smartcard!
        '''
        status = ISO7816.sw_status(sw1, sw2)
        if sw1 == 0x91: status = 'normal processing, with extra info ' \
            'containing a command for the terminal: length of the ' \
            'response data %d' % sw2
        elif sw1 == 0x9E: status = 'normal processing, SIM data download ' \
            'error: length of the response data %d' % sw2
        elif sw1 == 0x9F: status = 'normal processing: length of the ' \
            'response data %d' % sw2
        elif (sw1, sw2) == (0x93, 0x00): status = 'SIM application toolkit ' \
            'busy, command cannot be executed at present'
        elif sw1 == 0x92 :
            status = 'memory management'
            if sw2 < 16: status += ': command successful but after %d '\
                'retry routine' % sw2
            elif sw2 == 0x40: status += ': memory problem'
        elif sw1 == 0x94:
            status = 'referencing management'
            if sw2 == 0x00: status += ': no EF selected'
            elif sw2 == 0x02: status += ': out of range (invalid address)'
            elif sw2 == 0x04: status += ': file ID or pattern not found'
            elif sw2 == 0x08: status += ': file inconsistent with the command'
        elif sw1 == 0x98:
            status = 'security management'
            if sw2 == 0x02: status += ': no CHV initialized'
            elif sw2 == 0x04: status += ': access condition not fulfilled, ' \
                'at least 1 attempt left'
            elif sw2 == 0x08: status += ': in contradiction with CHV status'
            elif sw2 == 0x10: status += ': in contradiction with ' \
                'invalidation status'
            elif sw2 == 0x40: status += ': unsuccessful CHV verification, ' \
                'no attempt left'
            elif sw2 == 0x50: status += ': increase cannot be performed, ' \
                'max value reached'
            elif sw2 == 0x62: status += ': authentication error, ' \
                'application specific'
            elif sw2 == 0x63: status += ': security session expired'
        return status
    
    def verify_pin(self, pin='', pin_type=1):
        '''
        verify CHV1 (PIN code) or CHV2 with VERIFY APDU command
        call ISO7816 VERIFY method
        '''
        if pin_type in [1, 2] and type(pin) is str and \
        len(pin) == 4 and 0 <= int(pin) < 10000:
            PIN = [ord(i) for i in pin] + [0xFF, 0xFF, 0xFF, 0xFF]
            self.coms.push( self.VERIFY(P2=pin_type, Data=PIN) )
        else: 
            if self.dbg: 
                log(2, '(verify_pin) bad input parameters')
    
    def disable_pin(self, pin='', pin_type=1):
        '''
        disable CHV1 (PIN code) or CHV2 with DISABLE_CHV APDU command
        TIP: do it as soon as you can when you are working 
        with a SIM / USIM card for which you know the PIN!
        call ISO7816 DISABLE method
        '''
        if pin_type in [1, 2] and type(pin) is str and \
        len(pin) == 4 and 0 <= int(pin) < 10000:
            PIN = [ord(i) for i in pin] + [0xFF, 0xFF, 0xFF, 0xFF]
            self.coms.push( self.DISABLE_CHV(P2=pin_type, Data=PIN) )
        else:
            if self.dbg: 
                log(2, '(disable_pin) bad input parameters')
    
    def unblock_pin(self, pin_type=1, unblock_pin=''):
        '''
        WARNING: not correctly implemented!!!
            and PUK are in general 8 nums...
        TODO: make it correctly!
        APDU Tx de-activated

        unblock CHV1 (PIN code) or CHV2 with UNBLOCK_CHV APDU command 
        and set 0000 value for new PIN
        call ISO7816 UNBLOCK_CHV method
        '''
        log(1, '(unblock_pin) not implemented: aborting')
        return
        #if pin_type == 1: 
        #    pin_type = 0
        if pin_type in [0, 2] and type(unblock_pin) is str and \
        len(unblock_pin) == 4 and 0 <= int(unblock_pin) < 10000:
            UNBL_PIN = [ord(i) for i in unblock_pin] + [0xFF, 0xFF, 0xFF, 0xFF]
            #self.coms.push( self.UNBLOCK_CHV(P2=pin_type, Lc=0x10, \
            #                Data=UNBL_PIN + \
            #                [0x30, 0x30, 0x30, 0x30, 0xFF, 0xFF, 0xFF, 0xFF]) )
        else:
            if self.dbg: 
                log(2, '(unblock_pin) bad input parameters')
            #return self.UNBLOCK_CHV(P2=pin_type)
    
    def parse_file(self, Data=[]):
        '''
        parse_file(Data=[0x12, 0x34, 0x56, 0x89]) -> dict(file)
        
        parses a list of bytes returned when selecting a file
        interprets the content of some informative bytes for right accesses, 
        type / format of file... see TS 51.011
        works over the SIM file structure
        '''
        fil = {}
        fil['Size'] = Data[2]*0x100 + Data[3]
        fil['File Identifier'] = Data[4:6]
        fil['Type'] = ('RFU', 'MF', 'DF', '', 'EF')[Data[6]]
        fil['Length'] = Data[12]
        if fil['Type'] == 'MF' or fil['Type'] == 'DF':
            fil['DF_num'] = Data[14]
            fil['EF_num'] = Data[15]
            fil['codes_num'] = Data[16]
            fil['CHV1'] = ('not initialized','initialized')\
                          [(Data[18] & 0x80) / 0x80]\
                        + ': %d attempts remain' % (Data[18] & 0x0F)
            fil['unblock_CHV1'] = ('not initialized','initialized')\
                                  [(Data[19] & 0x80) / 0x80]\
                                + ': %d attempts remain' % (Data[19] & 0x0F)
            fil['CHV2'] = ('not initialized','initialized')\
                          [(Data[20] & 0x80) / 0x80]\
                        + ': %d attempts remain' % (Data[20] & 0x0F)
            fil['unblock_CHV2'] = ('not initialized','initialized')\
                                  [(Data[21] & 0x80) / 0x80]\
                                + ': %d attempts remain' % (Data[21] & 0x0F)
            if len(Data) > 23: 
                fil['Adm'] = Data[23:]
        elif fil['Type'] == 'EF':
            cond = ('ALW', 'CHV1', 'CHV2', 'RFU', 'ADM_4', 'ADM_5', 
                    'ADM_6', 'ADM_7', 'ADM_8', 'ADM_9', 'ADM_A',
                    'ADM_B', 'ADM_C', 'ADM_D', 'ADM_E', 'NEW')
            fil['UPDATE'] = cond[Data[8] & 0x0F]
            fil['READ'] = cond[Data[8] >> 4]
            fil['INCREASE'] = cond[Data[9] >> 4]
            fil['INVALIDATE'] = cond[Data[10] & 0x0F]
            fil['REHABILITATE'] = cond[Data[10] >> 4]
            fil['Status'] = ('not read/updatable when invalidated', 
                              'read/updatable when invalidated')\
                            [byteToBit(Data[11])[5]] \
                          + (': invalidated',': not invalidated')\
                            [byteToBit(Data[11])[7]]
            fil['Structure'] = ('transparent', 'linear fixed', '', 'cyclic')\
                               [Data[13]]
            if fil['Structure'] == 'cyclic': 
                fil['INCREASE'] = byteToBit(Data[7])[1]
            if len(Data) > 14: 
                fil['Record Length'] = Data[14]
        return fil
    
    def run_gsm_alg(self, RAND=16*[0x00]):
        '''
        self.run_gsm_alg( RAND ) -> ( SRES, Kc )
            RAND : list of bytes, length 16
            SRES : list of bytes, length 4
            Kc : list of bytes, length 8
            
        runs GSM authentication algorithm: 
            accepts any kind of RAND (old GSM fashion)
        feed with RAND 16 bytes value
        returns a list with SRES and Kc, or None on error
        '''
        if len(RAND) != 16:
            if self.dbg: 
                log(1, '(run_gsm_alg) bad RAND value: aborting')
            return None
        # select DF_GSM directory
        self.select([0x7F, 0x20])
        if self.coms()[2] != (0x90, 0x00): 
            if self.dbg >= 2: 
                log(3, '(run_gsm_alg) %s' % self.coms())
            return None
        # run authentication
        self.coms.push(self.INTERNAL_AUTHENTICATE(P1=0x00, P2=0x00, Data=RAND))
        if self.coms()[2][0] != 0x9F:
            if self.dbg >= 2: 
                log(3, '(run_gsm_alg) %s' % self.coms())
            return None
        # get authentication response
        self.coms.push(self.GET_RESPONSE(Le=self.coms()[2][1]))
        if self.coms()[2] != (0x90, 0x00):
            if self.dbg >= 2: 
                log(3, '(run_gsm_alg) %s' % self.coms())
            return None
        SRES, Kc = self.coms()[3][0:4], self.coms()[3][4:]
        return [ SRES, Kc ]
    
    def get_imsi(self):
        '''
        self.get_imsi() -> string(IMSI)
        
        reads IMSI value at address [0x6F, 0x07]
        returns IMSI string on success or None on error
        '''
        # select DF_GSM for SIM card
        self.select([0x7F, 0x20])
        if self.coms()[2] != (0x90, 0x00): 
            if self.dbg >= 2: 
                log(3, '(get_imsi) %s' % self.coms())
            return None
        
        # select IMSI file
        imsi = self.select([0x6F, 0x07])
        if self.coms()[2] != (0x90, 0x00): 
            if self.dbg >= 2: 
                log(3, '(get_imsi) %s' % self.coms())
            return None
        
        # and parse the received data into the IMSI structure
        if 'Data' in imsi.keys() and len(imsi['Data']) == 9:
            return decode_BCD(imsi['Data'])[3:]
        
        # if issue with the content of the DF_IMSI file
        if self.dbg >= 2: 
            log(3, '(get_imsi) %s' % self.coms())
        return None
    
    def get_services(self):
        '''
        self.get_imsi() -> None
        
        reads SIM Service Table at address [0x6F, 0x38]
        prints services allowed / activated
        returns None
        '''
        # select DF_GSM for SIM card
        self.select([0x7F, 0x20])
        if self.coms()[2] != (0x90, 0x00): 
            if self.dbg >= 2: 
                log(3, '(get_services) %s' % self.coms())
            return None
        
        # select SST file
        sst = self.select([0x6F, 0x38])
        if self.coms()[2] != (0x90, 0x00): 
            if self.dbg >= 2: 
                log(3, '(get_services) %s' % self.coms())
            return None
        
        # parse data and prints corresponding services
        if 'Data' in sst.keys() and len(sst['Data']) >= 2:
            return self.get_services_from_sst(sst['Data'])
    
    def read_services(self):
        serv = self.get_services()
        for s in serv:
            print s
    
    def get_services_from_sst(self, sst=[0, 0]):
        services = []
        cnt = 0
        for B in sst:
            # 2 bits per service -> 4 services per byte
            for i in range(0, 7, 2):
                cnt += 1
                if B & 2**i:
                    info = 'allocated'
                    if B & (2**i+1):
                        info += ' | activated'
                    services.append('%i : %s : %s' \
                                    % (cnt, SIM_service_table[cnt], info))
        return services
    
    def explore_fs(self, filename='sim_fs', emul=False):
        '''
        self.explore_fs(self, filename='sim_fs') -> void
            filename: file to write in information found
        
        brute force all file addresses from MF recursively 
        (until no more DF are found)
        write information on existing DF and file in the output file
        '''
        simfs_entries = MF_FS.keys()
        if not emul:
            self.explore_DF([], None, True)
        
        fd = open(filename, 'w')
        fd.write('\n### MF ###\n')
        f = self.select()
        write_dict(f, fd)
        fd.write('\n')
        #
        for f in self.FS:
            path = tuple(f['Absolut Path'])
            if path in simfs_entries:
                f['Name'] = MF_FS[path]
            write_dict(f, fd)
            fd.write('\n')
        
        fd.close()
    