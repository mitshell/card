# card

This is a Python project to help reading and accessing smartcards, mostly focused on
telecom smartcards and SIMs.
The project was originally developped around 2009, and keeps being maintained.
Any feedback and contribution are always welcomed !


## Table Of Content
- [Background](#Background)
- [Structure](#Structure)
- [Install](#Install)
   - [Prerequisites](#Prerequisites)
   - [Library install](#Library-install)
- [Usage](#Usage)
- [Contributing](#Contributing)
- [License](#License)
- [Examples](#Examples)
   - [ISO7816 session](#ISO7816-session)
   - [SIM session](#SIM-session)
   - [USIM session](#USIM-session)
   - [GP session](#GP-session)
   - [EMV session](#EMV-session)


## Background
Smartcards with electrical connectors are in general all compliant with the basis 
standard ISO7816 - part 1-2-3-4. Most of the ISO standards are not public, but you 
can have a good view on ISO7816 here:
[cardwerk website](http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816.aspx)
The principle is to communicate with the card over a serial interface, sending APDU commands, 
and receiving replies with always 2 bytes of SW codes and eventually more byte of data.

All the Subscriber Identity Module (abbr. SIM) and USIM cards are based on this ISO 7816 standard.
They are additionally based on ETSI and 3GPP standards.
ETSI standards are public, see [ETSI](http://www.etsi.org/deliver/etsi_ts/) ;
3GPP standards are too, see [3GPP](http://www.3gpp.org/specification-numbering).

SIM cards are easy to read as they are only mono-application:
check 3GPP TS 11.11 or TS 51.011.
UICC / USIM cards are some more evolved as they are multi-applications / multi-channels cards: 
check ETSI TS 101.221 and 3GPP TS 31.101 and 31.102.
Moreover, recent cards often holds more application, such as from 
[GlobalPlatform](https://globalplatform.org/specs-library/) (abbr. GP),
and may also support contact-less access based on the ISO 14443 standard.

The following _card_ library has been developped mostly for experiencing with SIM and USIM cards,
with a focus on they security procedures (e.g. mobile subscriber authentication).
Most of its content stays quite experimental.

It was originally developped for Python 2.6, supporting then Python 2.7.
Some efforts were made to support Python 3 (starting with 3.5).
Most of the library is known to work on Python 3, but it could happen that
some methods or functions have not been perfectly migrated.


## Structure
The library is entirely made of Python files under the _card_ directory.

It is splitted into the following files:
- _utils.py_: contains facilities for parsing TV, TLV, BER_TLV records and some other utility functions
- _ICC.py_: contains the 2 main classes:
    - _ISO7816_: which implements a little part of the ISO7816 (mainly part 4) standard
    - _UICC_: which implements part of the ETSI standard, and inherits from the ISO7816 class
- _SIM.py_: contains the _SIM_ class inheriting from the ISO7816 class, implementing part of TS 51.011
- _USIM.py_: contains the _USIM_ class inheriting from the UICC class, implementing part of TS 31.102
- _FS.py_: dictionnaries refencing SIM and USIM files addresses as described in those 3GPP standards
- _GP.py_: contains the _GP_ class inheriting from the UICC class, implementing few basic methods for application recognition
- _EMV.py_: contains the _EMV_ class inheriting from the UICC class, only supporting basic EMV AID scanning

Morevoer, scripts to configure sysmocom SIM / USIM cards are provided:
- _prog\_sysmo\_sim.py_: for programming the old sysmo-SIM
- _prog\_sysmo\_usim.py_: for programming the old sysmo-USIM
- _prog\_sysmo\_sjs1.py_: for programming the sysmo-USIM-SJS1


## Install

### Prerequisites
First of all, you need a smartcard reader. Some laptops have one integrated, 
otherwise, you can find USB-based readers (a well-known USB-reader provider is OmniKey).

Then, you need a middleware in your OS that will drive the smartcard reader and expose
a PC-SC (for PC SmartCard) compliant API.
Windows has a built-in smartcard service, Linux has the [pcsc-lite project](https://pcsclite.apdu.fr/).
This last one is packaged for all the main distribs, and installing is often a matter of _apt install pcscd_
or _rpm -ivh pcsc-lite_.

Finally, you need the Python wrapper for the PCSC API, which is brought by the
[pyscard](https://pypi.org/project/pyscard/) project. 

Optionally, you may need [pydot](https://pypi.org/project/pydot/) which is required in
case you want to generate a nice picture of your SIM card's filesystem graph, 
after scanning it.


### Library install
A setup.py script is provided at the root of the project, you just need to use it
to install the library (system-wide with _sudo_, or only for your user).

```
python3 setup.py install
```


## Usage
The library as such does not provide any specific service or application.
If you are interested to use it to build you own application, you can check the 
several [examples](#Examples), for a quick view on the main classes and methods
that may be of interest.
Otherwise, you can check the docstrings which are provided for most of the
classes and methods, or more simply check at the source code.

The 3 scripts _prog\_sysmo\_*.py_ can be used through their `personnalize()` class.
You will however need first to adapt / update their content for the different files 
you want to update in your SIM or USIM card.


## Contributing
Any contribution is always very welcomed ! It can come in different ways:
- in case you find some bugs, please open an issue in the project issue tracker,
   and provide detailed information regarding your configuration and the bug you 
   encountered ;
- in case you fixed a bug, or you did a nice addition or extension, do not hesitate
   to submit a pull request ;
- in case you are using this project in one of your application, or you just find
   it useful, do not hesitate to send an email: getting feedback is always a pleasure.

Please refrain from opening an issue however before you have read all the README.
Most of the basic questions regarding this project may be answered here.


## License
The project was historically licensed under the GPLv2, when it was originally released.
The detail of the license is provided in the _license.txt_ file.


## Examples
Here is a series of examples for using the main classes and methods of the library.
When communicating with the smartcard, _pyscard_ uses list of bytes (uint8 values).
Every APDU and communication with the smartcard is handled in this way also by _card_.

### ISO7816 session
The _ISO7816_ class within the _ICC_ module provides basic methods for many of the 
ISO7816 commands, together with a method to interpret SW codes returned by the card 
and methods to work with the smartcard filesystem.
It does not provide high-level methods and may not be of great help if you want to simply 
work with SIM cards. It provides however the following methods useful to do some
scanning of a card: _ATR\_scan()_, _bf\_cla()_ and _bf\_ins()_.
The last 2 methods being dangerous, I am not using them that often !

```
In [1]: from card.ICC import *

In [2]: c = ISO7816()

In [3]: c.ATR_scan()

smartcard reader: Alcor Micro AU9560 00 00

smart card ATR is: 3B 9F 96 80 3F C7 A0 80 31 E0 73 FE 21 1B 64 07 68 9A 00 82 90 00 B4
ATR analysis: 
TA1: 96
TD1: 80
TD2: 3f
TA3: c7
TB3: a0
supported protocols T=0,T=15
T=0 supported: True
T=1 supported: False
checksum: 180
	clock rate conversion factor: 512
	bit rate adjustment factor: 32
	maximum programming current: 50
	programming voltage: 5
	guard time: None
nb of interface bytes: 5
nb of historical bytes: 15
None

historical bytes: 80 31 E0 73 FE 21 1B 64 07 68 9A 00 82 90 00
checksum: 0xB4

using pcsc_scan ATR list file: /usr/share/pcsc/smartcard_list.txt
no ATR fingerprint found in file: /usr/share/pcsc/smartcard_list.txt

In [4]: help(c.bf_cla)
Signature: c.bf_cla(start=0, param=[164, 0, 0, 2, 63, 0])
Docstring:
bf_cla( start=int(starting CLA), 
        param=list(bytes for selecting file 0x3F, 0x00) ) ->
    list( CLA which could be supported )
    
tries all classes CLA codes to check the possibly supported ones
prints CLA suspected to be supported
returns the list of those CLA codes

WARNING: 
can block the card definitively
Do not do it with your own VISA / MASTERCARD
File:      ~/src/card/card/ICC.py
Type:      method

In [5]: help(c.bf_ins)
Signature: c.bf_ins(start=0)
Docstring:
bf_cla( start=int(starting INS) ) 
    -> list( INS which could be supported )
    
tries all instructions INS codes to check the supported ones
prints INS suspected to be supported
returns the list of those INS codes

WARNING: 
can block the card definitively
Do not do it with your own VISA / MASTERCARD
File:      ~/src/card/card/ICC.py
Type:      method

In [8]: c.bf_ins()
[DBG] (INS bruteforce) ['apdu: 00 00 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 01 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 02 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 03 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['DEACTIVATE FILE apdu: 00 04 00 00', 'sw1, sw2: 69 86 - checking error: command not allowed: command not allowed (no current EF)', (105, 134), []]
[DBG] (INS bruteforce) ['apdu: 00 05 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 06 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 07 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 08 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 09 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 0A 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 0B 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['ERASE RECORD(S) apdu: 00 0C 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 0D 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['ERASE BINARY apdu: 00 0E 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['ERASE BINARY apdu: 00 0F 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['TERMINAL PROFILE apdu: 00 10 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['apdu: 00 11 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[DBG] (INS bruteforce) ['FETCH apdu: 00 12 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
[...]
[DBG] (INS bruteforce) ['apdu: 00 6D 00 00', 'sw1, sw2: 6E 00 - checking error: class not supported', (110, 0), []]
---------------------------------------------------------------------------
CardConnectionException                   Traceback (most recent call last)
[...]

In [9]: c.disconnect()
```

The _ICC_ module also has a _UICC_ class, which has common methods for all UICC cards.
Those are used for accessing USIM or GlobalPlatform application, or any other card application,
through their Application ID (abbr. AID).

```
In [1]: from card.ICC import *

In [2]: u = UICC()

In [3]: u.get_AID()

In [4]: u.AID
Out[4]: 
[[160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0],
 [160, 0, 0, 0, 99, 80, 75, 67, 83, 45, 49, 53]]

In [5]: for aid in u.AID:
    ...:     print('%s: %s' % (aid, u.interpret_AID(aid)))
    ...:     
[160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0]: 3GPP || USIM || France || (255, 1) || (137, 0, 0, 1, 0)
[160, 0, 0, 0, 99, 80, 75, 67, 83, 45, 49, 53]: (160, 0, 0, 0, 99) || (80, 75) || (67, 83) || (45, 49) || (53,)

In [6]: u.disconnect()
```


### SIM session
The _SIM_ module has the _SIM_ class, to deal with SIM cards, accessing its filesystem,
reading or writing file content, and running some of its custom command such as:
- _verify\_pin()_, _disable\_pin()_, _enable\_pin()_ to manage the PIN code
- _get\_ICCID()_, _get\_imsi()_, _get\_services()_ to read some files from the SIM
- _run\_gsm\_algorithm()_ to run the SIM authentication algorithm

```
In [1]: from card.SIM import *

In [2]: s = SIM()

In [3]: s.disable_pin('0000')

In [4]: s.coms() # check the resulting APDU exchanged
Out[4]: 
['DISABLE PIN apdu: A0 26 00 01 08 30 30 30 30 FF FF FF FF',
 'sw1, sw2: 98 08 - security management: in contradiction with CHV status',
 (152, 8),
 []]

In [5]: # PIN was already disabled

In [6]: s.get_ICCID()
Out[6]: '89330128272014674300'

In [7]: s.get_imsi()
Out[7]: '208017201440443'

In [8]: s.get_services() # this checks services activated in the SIM service table
Out[8]: 
['1 : CHV1 disable function : allocated | activated',
 '2 : Abbreviated Dialling Numbers (ADN) : allocated | activated',
 '3 : Fixed Dialling Numbers (FDN) : allocated | activated',
 '4 : Short Message Storage (SMS) : allocated | activated',
 '7 : PLMN selector : allocated | activated',
 '9 : MSISDN : allocated | activated',
 '10 : Extension1 : allocated | activated',
 '11 : Extension2 : allocated | activated',
 '12 : SMS Parameters : allocated | activated',
 '13 : Last Number Dialled (LND) : allocated | activated',
 '14 : Cell Broadcast Message Identifier : allocated | activated',
 '15 : Group Identifier Level 1 : allocated | activated',
 '16 : Group Identifier Level 2 : allocated | activated',
 '17 : Service Provider Name : allocated | activated',
 '18 : Service Dialling Numbers (SDN) : allocated | activated',
 '25 : Data download via SMS-CB : allocated',
 '26 : Data download via SMS-PP : allocated | activated',
 '27 : Menu selection : allocated | activated',
 '29 : Proactive SIM : allocated | activated',
 '30 : Cell Broadcast Message Identifier Ranges : allocated | activated',
 '35 : Short Message Status Reports : allocated | activated',
 '38 : GPRS : allocated | activated',
 '42 : RUN AT COMMAND command : allocated | activated',
 '48 : Extended Capability Configuration Parameters : allocated | activated',
 '53 : Mailbox Dialling Numbers  : allocated',
 '54 : Message Waiting Indication Status : allocated | activated',
 '55 : Call Forwarding Indication Status : allocated | activated']

In [9]: s.run_gsm_alg( 16 * [0x12] ) # we pass the 16 bytes RAND challenge as argument                                                                        
Out[9]: [[89, 207, 185, 186], [240, 127, 197, 92, 185, 134, 144, 170]]

In [10]: # and get the 4 bytes RES and 8 bytes Kc

In [11]: s.select([0x7f, 0x10]) # select DF_GSM
Out[11]: 
{'Size': 65535,
 'File Identifier': [127, 16],
 'Type': 'DF',
 'Length': 21,
 'DF_num': 1,
 'EF_num': 14,
 'codes_num': 14,
 'CHV1': 'initialized: 3 attempts remain',
 'unblock_CHV1': 'initialized: 10 attempts remain',
 'CHV2': 'initialized: 3 attempts remain',
 'unblock_CHV2': 'initialized: 10 attempts remain',
 'Adm': [131, 0, 131, 0, 0, 0, 0, 0, 0, 0, 0]}

In [12]: s.select([0x6f, 0x40]) # select EF_MSISDN
Out[12]: 
{'Size': 140,
 'File Identifier': [111, 64],
 'Type': 'EF',
 'Length': 2,
 'UPDATE': 'CHV1',
 'READ': 'CHV1',
 'INCREASE': 'NEW',
 'INVALIDATE': 'ADM_5',
 'REHABILITATE': 'ADM_5',
 'Status': 'read/updatable when invalidated: not invalidated',
 'Structure': 'linear fixed',
 'Record Length': 28,
 'Data': []}

In [13]: # MSISDN file is empty in this SIM card

In [14]: s.coms() # the last exchanged APDU                                                                                                               
Out[14]: 
['READ RECORD(S) apdu: A0 B2 05 04 1C',
 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification',
 (144, 0),
 [255,
  [...]
  255]]

In [15]: s.coms # the last 10 exchanged APDU                                                                                                         
Out[15]: 
['GET RESPONSE apdu: A0 C0 00 00 0C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [89, 207, 185, 186, 240, 127, 197, 92, 185, 134, 144, 170]]
['SELECT FILE apdu: A0 A4 00 00 02 7F 10', 'sw1, sw2: 9F 22 - normal processing: length of the response data 34', (159, 34), []]
['GET RESPONSE apdu: A0 C0 00 00 22', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [0, 0, 255, 255, 127, 16, 2, 0, 127, 255, 255, 1, 21, 177, 1, 14, 14, 0, 131, 138, 131, 138, 0, 131, 0, 131, 0, 0, 0, 0, 0, 0, 0, 0]]
['SELECT FILE apdu: A0 A4 00 00 02 6F 40', 'sw1, sw2: 9F 0F - normal processing: length of the response data 15', (159, 15), []]
['GET RESPONSE apdu: A0 C0 00 00 0F', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [0, 0, 0, 140, 111, 64, 4, 0, 17, 255, 85, 5, 2, 1, 28]]
['READ RECORD(S) apdu: A0 B2 01 04 1C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['READ RECORD(S) apdu: A0 B2 02 04 1C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['READ RECORD(S) apdu: A0 B2 03 04 1C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['READ RECORD(S) apdu: A0 B2 04 04 1C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]
['READ RECORD(S) apdu: A0 B2 05 04 1C', 'sw1, sw2: 90 00 - normal processing: command accepted: no further qualification', (144, 0), [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]]

In [16]: s.disconnect()
```

When working to analyse a SIM card, it is often recommended to start with disabling 
the PIN code of the card. This is to avoid blocking the card by sending inappropriate
commands.

A method to scan the entire filesystem of the SIM card is available too. It bruteforces
all the file identifiers within directories (DF) recursively, starting from the master
file (MF) and writes all found MF / DF / EF metadata and potential content into a
text file. While doing so, a dict under the _FS_ attribute is also populated with
the content of the filesystem ; this further enables to produce a graph of the filesystem
with the _make\_graph()_ function.

```
In [1]: from card.SIM import *

In [2]: s = SIM()

In [3]: s.dbg = 1 # this is to check the progression of the scanning

In [4]: s.explore_fs('my_sim_fs.txt') # this takes a while, results will be dumped into ./my_sim_fs.txt

In [5]: g = make_graph(s.FS)

In [6]: g.write_png('my_sim_fs.png') # this creates a PNG file

In [7]: s.disconnect()
```

[Here](http://michau.benoit.free.fr/codes/smartcard/sysmoUSIM/) is an example of such 
SIM and USIM dumps and graphs.


### USIM session
The _USIM_ module has the _USIM_ class, to deal with the USIM application available on UICC cards.
Those are used with 3G, 4G and now 5G handsets and provide a dedicated USIM application 
with all the required parameters for accessing a 3G-4G-5G network.
When instantiated, the USIM AID is selected and the user is placed within the context of the application.

```
In [1]: from card.USIM import *

In [2]: u = USIM()

In [3]: u.AID # this is the list of every Application ID advertised by the UICC
Out[3]: 
[[160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0],
 [160, 0, 0, 0, 99, 80, 75, 67, 83, 45, 49, 53]]

In [4]: u.USIM_AID # this is the USIM AID that has been selected
Out[4]: [160, 0, 0, 0, 135, 16, 2, 255, 51, 255, 1, 137, 0, 0, 1, 0]

In [5]: u.interpret_AID(u.USIM_AID)                                                                                                                       
Out[5]: '3GPP || USIM || France || (255, 1) || (137, 0, 0, 1, 0)'

In [6]: u.get_imsi() # IMSI is also available in a file within the USIM
Out[6]: '208019701550443'

In [7]: u.get_CS_keys() # KSI, Ck, Ik for the CS domain
Out[7]: 
[[7],
 [85, 157, 127, 187, 70, 229, 55, 164, 70, 23, 245, 26, 36, 246, 143, 123],
 [7, 108, 190, 232, 10, 228, 58, 17, 100, 96, 4, 186, 140, 246, 35, 106]]

In [8]: u.get_PS_keys() # KSI, Ck, Ik for the PS domain
Out[8]: 
[[7],
 [190, 225, 254, 172, 22, 202, 165, 114, 81, 60, 199, 129, 244, 144, 125, 196],
 [227, 40, 142, 57, 129, 173, 5, 94, 135, 235, 95, 151, 100, 128, 62, 79]]

In [9]: u.get_services() # this checks services activated in the USIM service table
Out[9]: 
['2 : Fixed Dialling Numbers (FDN) : available',
 '3 : Extension 2 : available',
 '4 : Service Dialling Numbers (SDN) : available',
 '8 : Outgoing Call Information (OCI and OCT) : available',
 '9 : Incoming Call Information (ICI and ICT) : available',
 '10 : Short Message Storage (SMS) : available',
 '11 : Short Message Status Reports (SMSR) : available',
 '12 : Short Message Service Parameters (SMSP) : available',
 '14 : Capability Configuration Parameters 2 (CCP2) : available',
 '15 : Cell Broadcast Message Identifier  : available',
 '16 : Cell Broadcast Message Identifier Ranges  : available',
 '17 : Group Identifier Level 1 : available',
 '18 : Group Identifier Level 2 : available',
 '19 : Service Provider Name : available',
 '21 : MSISDN : available',
 '27 : GSM Access : available',
 '28 : Data download via SMS-PP : available',
 '32 : RUN AT COMMAND command : available',
 "33 : shall be set to '1' : available",
 '34 : Enabled Services Table : available',
 '35 : APN Control List (ACL) : available',
 '38 : GSM security context  : available',
 '39 : CPBCCH Information : available',
 '40 : Investigation Scan : available',
 '42 : Operator controlled PLMN selector with Access Technology : available',
 '45 : PLMN Network Name : available',
 '46 : Operator PLMN List : available',
 '51 : Service Provider Display Information : available']

In [10]: u.select([0x6f, 0x42]) # EF_SMSP
Out[10]: 
{'File Descriptor': [66, 33, 0, 44, 2],
 'Access': 'shareable',
 'Structure': 'linear fixed',
 'Type': 'EF working',
 'Record Length': 44,
 'Record Number': 2,
 'File Identifier': [111, 66],
 'Life Cycle Status': 'operational state - activated',
 'Security Attributes ref to expanded': [111, 6, 3],
 'Size': 88,
 'Short File Identifier': [],
 'Control': 'FCP',
 'Data': [[78,
   111,
   32,
   67,
   101,
   110,
   [...]
   0,
   240,
   255,
   255,
   255,
   255,
   0,
   0,
   168]]}

In [11]: u.authenticate(RAND=16*[0x12], ctx='2G') # use the USIM authenticate API for a 2G authentication
Out[11]: [[89, 207, 185, 186], [240, 127, 197, 92, 185, 134, 144, 170]]

In [12]: u.authenticate(RAND=16*[0x12], AUTN=16*[0x23], ctx='3G') # this won't work unless we provide an appropriate AUTN value

In [13]: u.coms()                                                                                                                                          
Out[13]: 
['INTERNAL AUTHENTICATE apdu: 00 88 00 81 22 10 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 10 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23',
 'sw1, sw2: 98 62 - security management: authentication error, incorrect MAC',
 (152, 98),
 []]

In [14]: u.disconnect()
```

The _select()_ method can be used similarly as with the SIM class, to access the content
of the USIM filestystem. One can still remark that the access control is not handled
as in the SIM, but is made of a reference to the EF_ARR file content (and is thus less
explicit). 
A similar _explore\_fs()_ method as with the _SIM_ class is available. It scans
all files within the USIM application context.

There is also a bunch of methods related to the 3GPP Generic Bootstrap Architecture 
(abbr. GBA) implemented, which are not exposed here. They are quite rare and may not be 
of interest for many users.


### GP session
The _GP_ module has a _GP_ class, to deal with the GlobalPlatform application sometimes
available within UICC cards. It is often used to manage the potential deployment and management
of additional (JavaCard) applications within the card, remotely.

Not that much is implemented related to GlobalPlatform, and people mainly interested in it
may prefer to check a project like [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro).

```
In [1]: from card.GP import *                                                                                                                             

In [2]: g = GP()                                                                                                                                          

In [3]: g.get_infos() # collect known GP files

In [4]: for info in g.interpret_infos():
    ...:     print(info)
    ...:     
[+] Tag 00.42: Issuer Identification Number
0102030405060708090A0B0C0D0E0F10
[+] Tag 00.45: Card Image Number
89330128162013574300
[+] Tag 00.66: Card Data
    [+] Card Recognition Data: {globalPlatform 1}
    [+] Card Management Type and Version: {globalPlatform 2 2 2}
    [+] Card Identification Scheme: {globalPlatform 3}
    [+] Secure Channel Protocol: {globalPlatform 4 2 85}
    [+] Secure Channel Protocol: {globalPlatform 4 0}
[+] Tag 00.C1: Sequence Counter of the default Key Version Number
0
[+] Tag 00.C2: Confirmation Counter
0
[+] Tag 00.CF: Key Diversification
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[+] Tag 00.E0: Key Information Template
[ [['private', 0], [1, 4, 128, 16]],
  [['private', 0], [2, 4, 128, 16]],
  [['private', 0], [3, 4, 128, 16]],
  [['private', 0], [1, 33, 128, 16]],
  [['private', 0], [2, 33, 128, 16]],
  [['private', 0], [3, 33, 128, 16]],
  [['private', 0], [1, 7, 128, 16]],
  [['private', 0], [2, 7, 128, 16]],
  [['private', 0], [3, 7, 128, 16]],
  [['private', 0], [1, 32, 128, 16]],
  [['private', 0], [2, 32, 128, 16]],
  [['private', 0], [3, 32, 128, 16]],
  [['private', 0], [1, 113, 128, 16]],
  [['private', 0], [1, 112, 128, 16]]]
[+] Tag 9F.7F: CPLC Complete
    [+] IC fabricator: 4750
    [+] IC type: 0000
    [+] OS id: 8231
    [+] OS date: 2102
    [+] OS level: 3322
    [+] Fabrication date: 0000
    [+] IC serial: 00000000
    [+] IC batch: 0000
    [+] Module fabricator: 0000
    [+] Packaging date: 0000
    [+] ICC manufacturer: 0000
    [+] IC embedding date: 0000
    [+] Pre-personalizer: 0000
    [+] IC pre-personalization date: 0000
    [+] IC pre-personalization equipment id: 00000000
    [+] IC personalizer: 0000
    [+] IC personalization date: 0000
    [+] IC presonalization equipment id: 00000000
[+] Tag FF.21: Extended Card Resources Information
[ [['contextual', 1], [14]],
  [['contextual', 2], [5, 70, 128]],
  [['contextual', 3], [57, 49]]]

In [5]: g.dbg = 1

In [6]: g.scan_p1p2() # to scan all P1 P2 parameters for GP files, this may take a while...
[DBG] > found 00.42:
[[['applicative', 2], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]]]
[DBG] > found 00.45:
[[['applicative', 5], [137, 51, 1, 40, 22, 32, 19, 87, 67, 0]]]
[...]

In [7]: g.disconnect()
```


### EMV session
TODO


