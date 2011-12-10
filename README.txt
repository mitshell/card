########################
# smartcard repository #
########################

Smartcards with electrical connectors are in general all compliant with the basis standard ISO7816 - part 1-2-3-4.
ISO standards are not public, but you can have a good view on it here: 
http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816.aspx
The principle is to communicate with the card over a serial link, sending APDU commands, 
and receiving replies with always SW codes and sometimes data.

All the SIM and USIM cards are based on these standards, and in addition, on ETSI and 3GPP standards.
ETSI standards are not public, 3GPP standards are (http://www.3gpp.org/specification-numbering).
SIM cards are easy to read as they are only mono-application: check 3GPP TS 11.11 or TS 51.011
USIM cards are some more evolved as they are multi-applications / multi-channels cards: 
check ETSI TS 101.221 and 3GPP TS 31.101 and 31.102

############
# card lib #
############
#
# /card/* directory
#

this is a new version, build from the older iso7816.py monolithic script, to request mainly SIM and USIM cards.
It needs python 2.6 (may work on older version: not tested), a smartcard reader (USB or RS-232), 
pcsc-lite driver and daemon and its python binding pyscard.

The library is now splitted in several files:
- utils.py: contains facilities for parsing TV, TLV, BER_TLV records and some other little functions used by others modules
- ICC.py: contains the 2 main classes: 
    - ISO7816: which implements a little part of the ISO standard
    - UICC: which implements part of the ETSI standard inheriting from the ISO7816 class
- SIM.py: contains the class SIM inheriting from ISO7816 class, implementing part of TS 51.011
- USIM.py: contains the class USIM inheriting from UICC class, implementing part of TS 31.102
- FS.py: dictionnaries refencing SIM and USIM files address as described in those 3GPP standards

All file addresses and data syntax are list of short integer (e.g. [0xAA, 0xBB, 0xCC, ...]), as used by pyscard.
Mistakes remains surely still in these scripts, so use it with care.
UICC and USIM classes do not implement logical channels.
ISO7816 and UICC security conditions parsing is really not well implemented.

SIM and USIM classes have a .scan_fs() method.
This allows to scan the ICC file-system from MF or AIDs recursively (enter DF each time one is found).
It gets file manament parameters, and file content if access right is OK,
and put every thing into a text file.

#####################
# example sessions: #
#####################

### a simple ISO7816 session ###
>>> a = ISO7816()
>>> a.ATR_scan()

smartcard reader:  Gemplus USB Smart Card Reader 0

smart card ATR is: 3B 9F 95 80 1F C7 80 31 E0 73 FE 21 1B 63 E2 08 A8 83 0F 90 00 89
ATR analysis: 
TA1: 95
TD1: 80
TD2: 1f
TA3: c7
supported protocols {'T=0': True, 'T=15': True}
T=0 supported True
T=1 supported False
checksum: 137
	clock rate conversion factor: 512
	bit rate adjustment factor: 16
	maximum programming current: 50
	programming voltage: 5
	guard time: None
nb of interface bytes: 4
nb of historical bytes: 15
None

historical bytes:  80 31 E0 73 FE 21 1B 63 E2 08 A8 83 0F 90 00
checksum:  0x89

using pcsc_scan ATR list file: C:/Python26/Lib/site-packages/card/smartcard_list.txt
smartcard ATR fingerprint:
Tre (Swedish operator)
# Hmmm... not sure my regex parsing of the pcsc smartcard_list.txt is correct...

# Warning while using dangerous CLA and INS bruteforce functions as cards often implement counter-measures such as definitive lock...
>>> a.bf_ins()
['DEACTIVATE FILE apdu: 00 04 00 00', 'sw1, sw2: 69 86 - checking error: command not allowed: command not allowed (no current EF)', (105, 134), []]
['TERMINAL PROFILE apdu: 00 10 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
['FETCH apdu: 00 12 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
['TERMINAL RESPONSE apdu: 00 14 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
['VERIFY apdu: 00 20 00 00', 'sw1, sw2: 6B 00 - checking error: wrong parameter(s) P1-P2', (107, 0), []]
['CHANGE PIN apdu: 00 24 00 00', 'sw1, sw2: 6B 00 - checking error: wrong parameter(s) P1-P2', (107, 0), []]
['DISABLE PIN apdu: 00 26 00 00', 'sw1, sw2: 6B 00 - checking error: wrong parameter(s) P1-P2', (107, 0), []]
['ENABLE PIN apdu: 00 28 00 00', 'sw1, sw2: 6B 00 - checking error: wrong parameter(s) P1-P2', (107, 0), []]
['PERFORM SECURITY OPERATION apdu: 00 2A 00 00', 'sw1, sw2: 69 82 - checking error: command not allowed: security status not satisfied', (105, 130), []]
['UNBLOCK PIN apdu: 00 2C 00 00', 'sw1, sw2: 6B 00 - checking error: wrong parameter(s) P1-P2', (107, 0), []]
['INCREASE apdu: 00 32 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
['ACTIVATE FILE apdu: 00 44 00 00', 'sw1, sw2: 69 86 - checking error: command not allowed: command not allowed (no current EF)', (105, 134), []]
['MANAGE CHANNEL apdu: 00 70 00 00', 'sw1, sw2: 6C 01 - checking error: wrong length Le: exact length is 01', (108, 1), []]
['apdu: 00 76 00 00', 'sw1, sw2: 67 00 - checking error: wrong length (P3 parameter)', (103, 0), []]
['apdu: 00 77 00 00', 'sw1, sw2: 69 82 - checking error: command not allowed: security status not satisfied', (105, 130), []]

Traceback (most recent call last):
  File "<pyshell#10>", line 1, in <module>
    a.bf_ins()
  File "C:\Python26\lib\site-packages\card\ICC.py", line 322, in bf_ins
    ret = self.sr_apdu([self.CLA, i, 0x00, 0x00])
  File "C:\Python26\lib\site-packages\card\ICC.py", line 281, in sr_apdu
    data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
  File "C:\Python26\lib\site-packages\smartcard\CardConnectionDecorator.py", line 81, in transmit
    return self.component.transmit( bytes, protocol )
  File "C:\Python26\lib\site-packages\smartcard\CardConnection.py", line 131, in transmit
    data, sw1, sw2 = self.doTransmit( bytes, protocol )
  File "C:\Python26\lib\site-packages\smartcard\pcsc\PCSCCardConnection.py", line 160, in doTransmit
    raise CardConnectionException( 'Failed to transmit with protocol ' + dictProtocolHeader[pcscprotocolheader] + '. ' + SCardGetErrorMessage(hresult) )
CardConnectionException: "Smartcard Exception: Failed to transmit with protocol T0. Une erreur de connexion avec la carte \xe0 puce a \xe9t\xe9 d\xe9tect\xe9e. R\xe9essayez l'op\xe9ration. !"

>>> a.disconnect()

### a SIM card session ###
>>> from card.SIM import *
>>> s = SIM()
>>> s.disable_pin('0123')

# check last request / response
>>> s.coms()
['DISABLE PIN apdu: A0 26 00 01 08 30 31 32 33 FF FF FF FF', 'sw1, sw2: 98 08 - security management: in contradiction with CHV status', (152, 8), []]
# SIM card PIN was already disabled

>>> s.run_gsm_alg(RAND = 16*[0xEE])
[[186, 6, 7, 233], [27, 138, 6, 159, 176, 99, 36, 76]]

# check the stack of 10 last requests / responses
>>> s.coms
['DISABLE PIN apdu: A0 26 00 01 08 30 31 32 33 FF FF FF FF', 'sw1, sw2: 98 08 - security management: in contradiction with CHV status', (152, 8), []]
['SELECT FILE apdu: A0 A4 00 00 02 7F 20', 'sw1, sw2: 9F 16 - normal processing: length of the response data 22', (159, 22), []]
['GET RESPONSE apdu: A0 C0 00 00 16', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [0, 0, 255, 255, 127, 32, 2, 0, 0, 0, 0, 0, 9, 177, 0, 26, 8, 0, 131, 138, 131, 138]]
['INTERNAL AUTHENTICATE apdu: A0 88 00 00 10 EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE', 'sw1, sw2: 9F 0C - normal processing: length of the response data 12', (159, 12), []]
['GET RESPONSE apdu: A0 C0 00 00 0C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [186, 6, 7, 233, 27, 138, 6, 159, 176, 99, 36, 76]]

>>> s.disconnect()


### a USIM card session ###
>>> from card.USIM import *
>>> u = USIM()
[+] UICC AID found:
[AID 1] 3GPP || USIM || France || (255, 1) || (137, 0, 0, 1, 0)
[+] USIM AID selection succeeded

>>> u.get_imsi()
'208XXXXXXXXXXX3'
>>> u.authenticate(RAND=16*[0xAA], ctx='2G')
[[73, 153, 135, 97], [204, 140, 250, 128, 34, 50, 232, 224]]
>>> u.coms()
['GET RESPONSE apdu: 00 C0 00 00 0E', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [4, 73, 153, 135, 97, 8, 204, 140, 250, 128, 34, 50, 232, 224]]
>>> u.coms
['GET RESPONSE apdu: 00 C0 00 00 28', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [98, 38, 130, 5, 66, 33, 0, 38, 2, 131, 2, 47, 0, 165, 6, 128, 1, 113, 192, 1, 64, 138, 1, 5, 139, 3, 47, 6, 3, 128, 2, 0, 76, 129, 2, 0, 90, 136, 1, 240]]
['READ RECORD(S) apdu: 00 B2 01 04 26', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [97, 24, 79, 16, 160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0, 80, 4, 85, 83, 73, 77, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['READ RECORD(S) apdu: 00 B2 02 04 26', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['SELECT FILE apdu: 00 A4 04 04 10 A0 00 00 00 87 10 02 FF 33 FF 01 89 00 00 01 00', 'sw1, sw2: 61 3E - normal processing: 62 bytes still available', (97, 62), []]
['GET RESPONSE apdu: 00 C0 00 00 3E', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [98, 60, 130, 2, 120, 33, 132, 16, 160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0, 165, 17, 128, 1, 113, 129, 3, 2, 10, 50, 130, 1, 30, 131, 4, 0, 2, 228, 128, 138, 1, 5, 139, 3, 47, 6, 2, 198, 9, 144, 1, 64, 131, 1, 1, 131, 1, 129]]
['SELECT FILE apdu: 00 A4 00 04 02 6F 07', 'sw1, sw2: 61 25 - normal processing: 37 bytes still available', (97, 37), []]
['GET RESPONSE apdu: 00 C0 00 00 25', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [98, 35, 130, 2, 65, 33, 131, 2, 111, 7, 165, 6, 128, 1, 113, 192, 1, 0, 138, 1, 5, 139, 3, 111, 6, 6, 128, 2, 0, 9, 129, 2, 0, 23, 136, 1, 56]]
['READ BINARY apdu: 00 B0 00 00 09', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [8, 41, 128, 16, 84, 84, 52, 6, 48]]
['INTERNAL AUTHENTICATE apdu: 00 88 00 80 11 10 AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA', 'sw1, sw2: 61 0E - normal processing: 14 bytes still available', (97, 14), []]
['GET RESPONSE apdu: 00 C0 00 00 0E', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [4, 73, 153, 135, 97, 8, 204, 140, 250, 128, 34, 50, 232, 224]]

>>> u.disconnect()

