import logging
import time
from typing import Any, Iterable, Optional, List, Tuple
from smartcard.CardType import AnyCardType, CardType
from serial import SerialException
from .at_command_client import ATCommandClient

logger = logging.getLogger("modem")

class ModemCardRequest:
    def __init__(self, modem_device_path, timeout: int = 1, cardType: CardType = AnyCardType, readers: Optional[Iterable[str]] = None) -> None:
        self._readers = readers or ['']
        self._client = ATCommandClient(modem_device_path, timeout=float(timeout))

    @property
    def connection(self) -> Any:
        return self

    def waitforcard(self) -> None:
        self.connect()
        return self

    def connect(self) -> None:
        self._client.connect()

    def getReader(self) -> Any:
        return self._readers
    
    def getATR(self) -> Any:
        return None
    
    def transmit(self, apdu: List[int]) -> Any:
        """
            Transmits SIM APDU to the modem.
        """

        at_command = self._to_csim_command(apdu)
        data, sw1, sw2 = [], 0xff, 0xff

        try:
            while sw1 == 0xff and sw2 == 0xff:
                data, sw1, sw2 = self._client.transmit(at_command, self._at_response_to_card_response)
        except SerialException as e:
            logger.debug("Serial communication error << {e} ... retrying") # for faulty, unstable cards

        logger.debug(f"""
            APDU << {apdu}
            AT Command << {at_command}
            Ret << data:{data}, sw1:{sw1}, sw2:{sw2}
        """)
        return (data, sw1, sw2)
        
    def _to_csim_command(self, apdu: List[int]) -> str:
        """
            Transforms a SIM APDU represented as a list of integers (bytes data)
            into its corresponding AT+CSIM command format.
        """

        at_command = ("").join(map(lambda x: "%0.2X" % x, apdu))
        at_command = f'AT+CSIM={len(at_command)},"{at_command}"'
        return at_command

    def _at_response_to_card_response(self, at_command: str, at_response: str) -> Tuple[List[int], int, int]:
        """
            Transforms AT response to the expected CardService format.
        """

        parts = list(filter(lambda x: x != '', at_response.split("\r\n")))
        if len(parts) == 0:
            return [], 0xff, 0xff # communication error

        if not parts[-1] or 'ERROR' in parts[-1]:
            return [], 0x6f, 0x0 # checking error: no precise diagnosis
        
        res = parts[0]
        res = res[res.find('"')+1:-1:]

        return (
            self._hexstream_to_bytes(res[:-4:]),
            int(res[-4:-2:], 16),
            int(res[-2::], 16)
        )

    def _hexstream_to_bytes(self, hexstream: str) -> List[int]:
        """
            Returns a list of integers representing byte data from a hexadecimal stream.
        """

        return list(
            map(
                lambda x: int(x, 16),
                [hexstream[i:i+2] for i in range(0, len(hexstream), 2)]
            )
        ) 

