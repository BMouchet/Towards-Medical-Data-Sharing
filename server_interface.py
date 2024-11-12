from abc import ABC, abstractmethod

class ServerInterface(ABC):

    @abstractmethod
    def start_server(self):
        pass

    @abstractmethod
    def stop_server(self):
        pass

