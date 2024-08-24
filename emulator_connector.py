import requests
import time

class EmulatorConnector():
    on_update_handlers = []
    def __init__(self, port):
        self.port = port

    def registers(self) -> dict[str, int]:
        r = requests.get(f"http://localhost:{self.port}/registers")
        if r.status_code == 200:
            return r.json()
        else:
            raise Exception(f"Failed to get registers: {r.status_code}")

    def register_on_update_handler(self, handler):
        self.on_update_handlers.append(handler)

    def __on_update(self):
        time.sleep(0.1)
        for handler in self.on_update_handlers:
            handler()

    def quit(self):
        requests.get(f"http://localhost:{self.port}/control/quit")
        self.__on_update()

    def step(self):
        requests.get(f"http://localhost:{self.port}/control/step")
        self.__on_update()

    def cont(self):
        requests.get(f"http://localhost:{self.port}/control/continue")
        self.__on_update()

    def brk(self):
        requests.get(f"http://localhost:{self.port}/control/break")
        self.__on_update()

    def read_word(self, address):
        url = f"http://localhost:{self.port}/read/word/{hex(address)}"
        r = requests.get(url)
        if r.status_code != 200:
            raise Exception(f"Failed to read word at {hex(address)}: {r.status_code} from url {url}")
        return r.text