import time
import serial
from typing import Optional, Union, Callable, Any

class ATCommandClient:

    def __init__(self, device_path: str, timeout: Optional[float] = 1.0) -> None:
        if timeout < 0.5:
            timeout = 0.5

        self._device_path = device_path
        self._timeout = timeout
        self._serial = None

    def connect(self) -> None:
        if self._serial:
            return

        self._serial = serial.Serial(
            self._device_path, 
            115200, 
            timeout=0.001,
        )

    def transmit(self, at_command: Union[str, bytes], transform: Optional[Callable[[str, str], Any]] = lambda x,y: y) -> Union[str, Any]:
        if not self._serial:
            raise ValueError("Client shall be connected")
        
        if isinstance(at_command, bytes):
            at_command = at_command.decode()

        if at_command[-2::] != "\r\n":
            at_command += "\r\n"

        at_command = at_command.encode()
        self._serial.write(at_command)

        resp = b''
        read_until = time.time() + self._timeout
        while b'OK' not in resp and b'ERROR' not in resp:        
            resp += self._serial.read(256)
            if time.time() > read_until:
                break

        return transform(at_command, resp.decode())

    def dispose(self) -> None:
        if not self._serial:
            return

        self._serial.close()
        self._serial = None        
    