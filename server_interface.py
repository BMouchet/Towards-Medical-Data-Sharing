from abc import ABC, abstractmethod

class ServerInterface(ABC):

    @abstractmethod
    def start_server(self):
        pass

    @abstractmethod
    def stop_server(self):
        pass

    @abstractmethod
    def accept_connection(self):
        pass

    @abstractmethod
    def send_data(self, data):
        pass

    @abstractmethod
    def receive_data(self):
        pass
