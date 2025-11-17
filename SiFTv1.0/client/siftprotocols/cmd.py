# Command Protocol Implementation for SiFT v1.0

class CommandProtocol:
    def __init__(self, connection):
        self.connection = connection

    def send_command(self, command, *params):
        message = self._format_command(command, *params)
        self.connection.send(message)

    def _format_command(self, command, *params):
        command_message = command + '\n'
        for param in params:
            command_message += param + '\n'
        return command_message.strip().encode('utf-8')

    def receive_response(self):
        response = self.connection.recv(4096)  # Adjust buffer size as needed
        return response.decode('utf-8').strip()