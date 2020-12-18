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
# Python library to work on
# USIM card
# communication based on ISO7816 card
# and commands and formats based on UICC card
#
# needs pyscard from:
# http://pyscard.sourceforge.net/
#################################

from card.ICC import UICC, ISO7816
from card.SIM import SIM
from card.FS import USIM_app_FS
from card.utils import *

USIM_service_table = {
    1 : 'Local Phone Book',
    2 : 'Fixed Dialling Numbers (FDN)',
    3 : 'Extension 2',
    4 : 'Service Dialling Numbers (SDN)',
    5 : 'Extension3',
    6 : 'Barred Dialling Numbers (BDN)',
    7 : 'Extension4',
    8 : 'Outgoing Call Information (OCI and OCT)',
    9 : 'Incoming Call Information (ICI and ICT)',
    10 : 'Short Message Storage (SMS)',
    11 : 'Short Message Status Reports (SMSR)',
    12 : 'Short Message Service Parameters (SMSP)',
    13 : 'Advice of Charge (AoC)',
    14 : 'Capability Configuration Parameters 2 (CCP2)',
    15 : 'Cell Broadcast Message Identifier ',
    16 : 'Cell Broadcast Message Identifier Ranges ',
    17 : 'Group Identifier Level 1',
    18 : 'Group Identifier Level 2',
    19 : 'Service Provider Name',
    20 : 'User controlled PLMN selector with Access Technology',
    21 : 'MSISDN',
    22 : 'Image (IMG)',
    23 : 'Support of Localised Service Areas (SoLSA) ',
    24 : 'Enhanced Multi-Level Precedence and Pre-emption Service',
    25 : 'Automatic Answer for eMLPP',
    26 : 'RFU',
    27 : 'GSM Access',
    28 : 'Data download via SMS-PP',
    29 : 'Data download via SMS-CB',
    30 : 'Call Control by USIM',
    31 : 'MO-SMS Control by USIM',
    32 : 'RUN AT COMMAND command',
    33 : 'shall be set to \'1\'',
    34 : 'Enabled Services Table',
    35 : 'APN Control List (ACL)',
    36 : 'Depersonalisation Control Keys',
    37 : 'Co-operative Network List',
    38 : 'GSM security context ',
    39 : 'CPBCCH Information',
    40 : 'Investigation Scan',
    41 : 'MexE',
    42 : 'Operator controlled PLMN selector with Access Technology',
    43 : 'HPLMN selector with Access Technology',
    44 : 'Extension 5',
    45 : 'PLMN Network Name',
    46 : 'Operator PLMN List',
    47 : 'Mailbox Dialling Numbers ',
    48 : 'Message Waiting Indication Status',
    49 : 'Call Forwarding Indication Status',
    50 : 'Reserved and shall be ignored',
    51 : 'Service Provider Display Information',
    52 : 'Multimedia Messaging Service (MMS)',
    53 : 'Extension 8',
    54 : 'Call control on GPRS by USIM',
    55 : 'MMS User Connectivity Parameters',
    56 : 'Network\'s indication of alerting in the MS (NIA)',
    57 : 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
    58 : 'VBS Group Identifier List (EFVBS and EFVBSS)',
    59 : 'Pseudonym',
    60 : 'User Controlled PLMN selector for I-WLAN access',
    61 : 'Operator Controlled PLMN selector for I-WLAN access',
    62 : 'User controlled WSID list',
    63 : 'Operator controlled WSID list',
    64 : 'VGCS security',
    65 : 'VBS security',
    66 : 'WLAN Reauthentication Identity',
    67 : 'Multimedia Messages Storage',
    68 : 'Generic Bootstrapping Architecture (GBA)',
    69 : 'MBMS security',
    70 : 'Data download via USSD and USSD application mode',
    71 : 'Equivalent HPLMN',
    72 : 'Additional TERMINAL PROFILE after UICC activation',
    73 : 'Equivalent HPLMN Presentation Indication',
    74 : 'Last RPLMN Selection Indication',
    75 : 'OMA BCAST Smart Card Profile',
    76 : 'GBA-based Local Key Establishment Mechanism',
    77 : 'Terminal Applications',
    78 : 'Service Provider Name Icon',
    79 : 'PLMN Network Name Icon',
    80 : 'Connectivity Parameters for USIM IP connections',
    81 : 'Home I-WLAN Specific Identifier List',
    82 : 'I-WLAN Equivalent HPLMN Presentation Indication',
    83 : 'I-WLAN HPLMN Priority Indication',
    84 : 'I-WLAN Last Registered PLMN',
    85 : 'EPS Mobility Management Information',
    86 : 'Allowed CSG Lists and corresponding indications',
    87 : 'Call control on EPS PDN connection by USIM',
    88 : 'HPLMN Direct Access',
    89 : 'eCall Data',
    90 : 'Operator CSG Lists and corresponding indications',
    91 : 'Support for SM-over-IP',
    92 : 'Support of CSG Display Control',
    93 : 'Communication Control for IMS by USIM',
    94 : 'Extended Terminal Applications',
    95 : 'Support of UICC access to IMS',
    96 : 'Non-Access Stratum configuration by USIM',
    97 : 'PWS configuration by USIM',
    98 : 'RFU',
    99 : 'URI support by UICC',
    100: 'Extended EARFCN support',
    101: 'ProSe',
    102: 'USAT Application Pairing',
    103: 'Media Type support',
    104: 'IMS call disconnection cause',
    105: 'URI support for MO SHORT MESSAGE CONTROL',
    106: 'ePDG configuration Information support',
    107: 'ePDG configuration Information configured',
    108: 'ACDC support',
    109: 'Mission Critical Services',
    110: 'ePDG configuration Information for Emergency Service support',
    111: 'ePDG configuration Information for Emergency Service configured',
    112: 'eCall Data over IMS',
    113: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111',
    114: 'From Preferred',
    115: 'IMS configuration data',
    116: 'TV configuration',
    117: '3GPP PS Data Off',
    118: '3GPP PS Data Off Service List',
    119: 'V2X',
    120: 'XCAP Configuration Data',
    121: 'EARFCN list for MTC/NB-IOT UEs',
    122: '5GS Mobility Management Information',
    123: '5G Security Parameters',
    124: 'Subscription identifier privacy support',
    125: 'SUCI calculation by the USIM',
    126: 'UAC Access Identities support',
    127: 'Control plane-based steering of UE in VPLMN',
    128: 'Call control on PDU Session by USIM',
    129: '5GS Operator PLMN List',
    130: 'Support for SUPI of type network specific identifier',
    }


class USIM(UICC):
    """
    defines attributes, methods and facilities for ETSI / 3GPP USIM card
    check USIM specifications in 3GPP TS 31.102
    
    inherits (eventually overrides) methods and objects from UICC class
    use self.dbg = 1 or more to print live debugging information
    """
    
    def __init__(self, reader=''):
        """
        initializes like an ISO7816-4 card with CLA=0x00
        and checks available AID (Application ID) read from EF_DIR
        
        initializes on the MF
        """
        # initialize like a UICC
        ISO7816.__init__(self, CLA=0x00, reader=reader)
        self.AID = []
        #
        if self.dbg >= 2:
            log(3, '(UICC.__init__) type definition: %s' % type(self))
            log(3, '(UICC.__init__) CLA definition: %s' % hex(self.CLA))
        #
        self.SELECT_ADF_USIM()
    
    def SELECT_ADF_USIM(self):
        # USIM selection from AID
        if self.dbg:
            log(3, '(USIM.__init__) UICC AID found:')
        self.get_AID()
        for aid in self.AID:
            if  tuple(aid[0:5]) == (0xA0, 0x00, 0x00, 0x00, 0x87) \
            and tuple(aid[5:7]) == (0x10, 0x02) :
                usim = self.select(addr=aid, type='aid')
                if usim is None and self.dbg:
                    log(2, '(USIM.__init__) USIM AID selection failed')
                if usim is not None:
                    self.USIM_AID = aid
                    if self.dbg >= 2:
                        log(3, '(USIM.__init__) USIM AID selection succeeded\n')
    
    @staticmethod
    def sw_status(sw1, sw2):
        status = SIM.sw_status(sw1, sw2)
        if sw1 == 0x98 and sw2 in (0x62, 0x64, 0x65, 0x66, 0x67):
            status = 'security management'
            if sw2 == 0x62: status += ': authentication error, ' \
                'incorrect MAC'
            elif sw2 == 0x64: status += ': authentication error, ' \
                'security context not supported'
            elif sw2 == 0x65: status += ': key freshness failure'
            elif sw2 == 0x66: status += ': authentication error, ' \
                'no memory space available'
            elif sw2 == 0x67: status += ': authentication error, ' \
                'no memory space available in EF_MUK'
        return status
    
    def get_imsi(self):
        """
        get_imsi() -> string(IMSI)
        
        reads IMSI value at address [0x6F, 0x07]
        returns IMSI string on success or None on error
        """
        # select IMSI file
        imsi = self.select([0x6F, 0x07])
        if imsi is None: 
            return None
        # and parse the received data into the IMSI structure
        if 'Data' in imsi.keys() and len(imsi['Data']) == 9:
            return decode_BCD(imsi['Data'])[3:]
        
        # if issue with the content of the DF_IMSI file
        if self.dbg >= 2: 
            log(3, '(get_imsi) %s' % self.coms())
        return None
    
    def get_CS_keys(self):
        """
        get_CS_keys() -> [KSI, CK, IK]
        
        reads CS UMTS keys at address [0x6F, 0x08]
        returns list of 3 keys, each are list of bytes, on success 
            (or eventually the whole file dict if the format is strange)
        or None on error
        """
        EF_KEYS = self.select( [0x6F, 0x08] )
        if self.coms()[2] == (0x90, 0x00):
            if len(EF_KEYS['Data']) == 33:
                KSI, CK, IK = ( EF_KEYS['Data'][0:1],
                                EF_KEYS['Data'][1:17],
                                EF_KEYS['Data'][17:33])
                if self.dbg >= 2:
                    log(3, '(get_CS_keys) successful CS keys selection: ' \
                            'Get [KSI, CK, IK]')
                return [KSI, CK, IK]
            else: 
                return EF_KEYS
        return None
    
    def get_PS_keys(self):
        """
        get_PS_keys() -> [KSI, CK_PS, IK_PS]
        
        reads PS UMTS keys at address [0x6F, 0x09]
        returns list of 3 keys, each are list of bytes, on success 
            (or eventually the whole file dict if the format is strange)
        or None on error
        """
        EF_KEYSPS = self.select( [0x6F, 0x09] )
        if self.coms()[2] == (0x90, 0x00):
            if len(EF_KEYSPS['Data']) == 33:
                KSI, CK, IK = ( EF_KEYSPS['Data'][0:1], 
                                EF_KEYSPS['Data'][1:17], 
                                EF_KEYSPS['Data'][17:33] )
                if self.dbg >= 2:
                    log(3, '(get_PS_keys) successful PS keys selection: ' \
                            'Get [KSI, CK, IK]')
                return [KSI, CK, IK]
            else: 
                return EF_KEYSPS
        return None
    
    def get_GBA_BP(self):
        """
        get_GBA_BP() -> [[RAND, B-TID, KeyLifetime], ...], 
        Length-Value parsing style
        
        reads EF_GBABP file at address [0x6F, 0xD6], 
            containing RAND and associated B-TID and KeyLifetime
        returns list of list of bytes on success 
            (or eventually the whole file dict if the format is strange)
        or None on error
        """
        EF_GBABP = self.select( [0x6F, 0xD6] )
        if self.coms()[2] == (0x90, 0x00):
            if len(EF_GBABP['Data']) > 2:
                #RAND, B_TID, Lifetime = LV_parser( EF_GBABP['Data'] )
                if self.dbg >= 2:
                    log(3, '(get_GBA_BP) successful GBA_BP selection: ' \
                           'Get list of [RAND, B-TID, KeyLifetime]')
                #return (RAND, B_TID, Lifetime)
                return LV_parser( EF_GBABP['Data'] )
            else: 
                return EF_GBABP
        return None
    
    def update_GBA_BP(self, RAND, B_TID, key_lifetime):
        """
        update_GBA_BP([RAND], [B_TID], [key_lifetime]) 
            -> None (or EF_GBABP file dict if RAND not found)
        
        reads EF_GBABP file at address [0x6F, 0xD6],
        checks if RAND provided is referenced, 
        and updates the file structure with provided B-TID and KeyLifetime
        returns nothing (or eventually the whole file dict
        if the RAND is not found)
        """
        GBA_BP = self.get_GBA_BP()
        for i in GBA_BP:
            if i == RAND:
                if self.dbg:
                    log(3, '(update_GBA_BP) RAND found in GBA_BP')
                # update transparent file with B_TID and key lifetime
                self.coms.push( self.UPDATE_BINARY( P2=len(RAND)+1,
                                Data=[len(B_TID)] + B_TID + \
                                [len(key_lifetime)] + key_lifetime ))
                if self.dbg >= 2: 
                    log(3, '(update_GBA_BP) %s' % self.coms())
                if self.coms()[2] == 0x90 and self.dbg:
                    log(3, '(update_GBA_BP) successful GBA_BP update with ' \
                           'B-TID and key lifetime')
                if self.dbg:
                    log(3, '(update_GBA_BP) new value of EF_GBA_BP:\n%s' \
                           % self.get_GBA_BP())
            else:
                if self.dbg:
                    log(2, '(update_GBA_BP) RAND not found in GBA_BP')
                return GBA_BP
    
    def get_GBA_NL(self):
        """
        get_GBA_NL() -> [[NAF_ID, B-TID], ...] , TLV parsing style
        
        reads EF_GBANL file at address [0x6F, 0xDA], containing NAF_ID and B-TID
        returns list of list of bytes vector on success 
            (or eventually the whole file dict if the format is strange)
        or None on error
        """
        EF_GBANL = self.select( [0x6F, 0xDA] )
        if self.coms()[2] == (0x90, 0x00):
            if len(EF_GBANL['Data'][0]) > 2:
                # This is Tag-Length-Value parsing, 
                # with 0x80 for NAF_ID and 0x81 for B-TID
                values = []
                for rec in EF_GBANL['Data']:
                    NAF_ID, B_TID = [], []
                    while len(rec) > 0:
                        tlv = first_TLV_parser( rec )
                        if tlv[1] > 0xFF:
                            rec = rec[ tlv[1]+4 : ]
                        else:
                            rec = rec[ tlv[1]+2 : ]
                        if tlv[0] == 0x80: 
                            NAF_ID = tlv[2]
                        elif tlv[0] == 0x81: 
                            B_TID = tlv[2]
                    values.append( [NAF_ID, B_TID] )
                if self.dbg:
                    log(3, '(get_GBA_NL) Successful GBA_NL selection: ' \
                           'Get list of [NAF_ID, B-TID]')
                #return (NAF_ID, B_TID)
                return values
            else: 
                return EF_GBANL
        return None
    
    def authenticate(self, RAND=[], AUTN=[], ctx='3G'):
        """
        self.authenticate(RAND, AUTN, ctx='3G') -> [key1, key2...], 
        LV parsing style
        
        runs the INTERNAL AUTHENTICATE command in the USIM 
        with the right context:
            ctx = '2G', '3G', 'GBA' ('MBMS' or other not supported at this time)
            RAND and AUTN are list of bytes; for '2G' context, AUTN is not used
        returns a list containing the keys (list of bytes) computed in the USIM,
        on success:
            [RES, CK, IK (, Kc)] or [AUTS] for '3G'
            [RES] or [AUTS] for 'GBA'
            [RES, Kc] for '2G'
        or None on error
        """
        # prepare input data for authentication
        if ctx in ('3G', 'VGCS', 'GBA', 'MBMS') and len(RAND) != 16 \
        and len(AUTN) != 16:
            if self.dbg:
                log(1, '(authenticate) bad AUTN parameter: aborting')
            return None
        #
        inp = []
        if ctx == '3G':
            P2 = 0x81
        elif ctx == 'VGCS':
            P2 = 0x82
            if self.dbg:
                log(1, '(authenticate) VGCS auth not implemented: aborting')
            return None
        elif ctx == 'MBMS':
            if self.dbg:
                log(1, '(authenticate) MBMS auth not implemented: aborting')
            return None
        elif ctx == 'GBA': 
            P2 = 0x84
            inp = [0xDD]
        inp.extend( [len(RAND)] + RAND + [len(AUTN)] + AUTN )
        if ctx not in ['3G', 'VGCS', 'MBMS', 'GBA']: 
        # and also, if ctx == '2G'... the safe way 
        # to avoid desynchronizing our USIM counter
            P2 = 0x80
            if len(RAND) != 16:
                if self.dbg:
                    log(1, '(authenticate) bad RAND parameter: aborting')
                return None
            # override input value for 2G authent
            inp = [len(RAND)] + RAND
            
        self.coms.push( self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp) )
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push( self.GET_RESPONSE(Le=self.coms()[2][1]) )
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                if P2 == 0x80:
                    if self.dbg:
                        log(3, '(authenticate) successful 2G authentication. ' \
                               'Get [RES, Kc]')
                    values = LV_parser(val)
                    # returned values are (RES, Kc)
                    return values
                # not adapted to 2G context with Kc, RES: to be confirmed...
                if val[0] == 0xDB:
                    if P2 == 0x81 and self.dbg: 
                        log(3, '(authenticate) successful 3G authentication. ' \
                               'Get [RES, CK, IK(, Kc)]')
                    elif P2 == 0x84 and self.dbg: 
                        log(3, '(authenticate) successful GBA authentication.' \
                               ' Get [RES]')
                    values = LV_parser(val[1:])
                    # returned values can be (RES, CK, IK) or (RES, CK, IK, Kc)
                    return values
                elif val[0] == 0xDC:
                    if self.dbg:
                        log(2, '(authenticate) synchronization failure. ' \
                               'Get [AUTS]')
                    values = LV_parser(val[1:])
                    return values
        #else:
        if self.dbg:
            log(1, '(authenticate) error: %s' % self.coms())
        return None
    
    def GBA_derivation(self, NAF_ID=[], IMPI=[]):
        """
        self.GBA_derivation(NAF_ID, IMPI) -> [Ks_ext_naf]
        
        runs the INTERNAL AUTHENTICATE command in the USIM 
        with the GBA derivation context:
            NAF_ID is a list of bytes (use stringToByte())
                "NAF domain name"||"security protocol id", 
                eg: "application.org"||"0x010001000a" (> TLS with RSA and SHA)
            IMPI is a list of bytes
                "IMSI@ims.mncXXX.mccYYY.3gppnetwork.org" if no IMS IMPI
                is specifically defined in the USIM 
        returns a list with GBA ext key (list of bytes) computed in the USIM:
            [Ks_ext_naf]
            Ks_int_naf remains available in the USIM 
            for further GBA_U key derivation
        or None on error
        
        see TS 33.220 for GBA specific formats
        """
        # need to run 1st an authenicate command with 'GBA' context, 
        # so to have the required keys in the USIM
        P2 = 0x84
        inp = [0xDE] + [len(NAF_ID)] + NAF_ID + [len(IMPI)] + IMPI
        
        self.coms.push( self.INTERNAL_AUTHENTICATE(P2=P2, Data=inp) )
        if self.coms()[2][0] in (0x9F, 0x61):
            self.coms.push( self.GET_RESPONSE(Le=self.coms()[2][1]) )
            if self.coms()[2] == (0x90, 0x00):
                val = self.coms()[3]
                if val[0] == 0xDB: # not adapted to 2G context with Kc, RES
                    if self.dbg: 
                        log(3, '(GBA_derivation) successful GBA derivation. ' \
                               'Get [Ks_EXT_NAF]')
                    values = LV_parser(val[1:])
                    return values
        if self.dbg: 
            log(3, '(GBA_derivation) authentication failure: %s' % self.coms())
        return None
    
    def get_services(self):
        """
        self.get_services() -> None
        
        reads USIM Service Table at address [0x6F, 0x38]
        prints services allowed / activated
        returns None
        """
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
            print(s)
    
    def get_services_from_sst(self, sst=[0, 0]):
        services = []
        cnt = 0
        for B in sst:
            # 1 bit per service -> 8 services per byte
            for i in range(0, 8):
                cnt += 1
                if B & 2**i:
                    if cnt in USIM_service_table:
                        services.append('%i : %s : available' \
                                        % (cnt, USIM_service_table[cnt]))
                    else:
                        services.append('%i : available' % cnt)
        return services
    
    def explore_fs(self, filename='usim_fs.txt', depth=2):
        """
        self.explore_fs(self, filename='usim_fs', depth=2) -> None
            filename: file to write in information found
            depth: depth in recursivity, True=infinite
        
        brute force all file addresses from 1st USIM AID
        with a maximum recursion level (to avoid infinite looping...)
        write information on existing DF and file in the output file
        """
        usimfs_entries = USIM_app_FS.keys()
        self.explore_DF([], self.AID.index(self.USIM_AID)+1, depth)
        
        fd = open(filename, 'w')
        fd.write('\n### AID %s ###\n' % self.USIM_AID)
        f = self.select_by_aid( self.AID.index(self.USIM_AID)+1 )
        write_dict(f, fd)
        fd.write('\n')
        #
        for f in self.FS:
            path = tuple(f['Absolut Path'])
            if path in usimfs_entries:
                f['Name'] = USIM_app_FS[path]
            write_dict(f, fd)
            fd.write('\n')
        
        fd.close()

