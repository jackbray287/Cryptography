import unittest
from client.siftprotocols.login import LoginProtocol

class TestLoginProtocol(unittest.TestCase):

    def setUp(self):
        self.login_protocol = LoginProtocol()

    def test_login_success(self):
        username = "alice"
        password = "aaa"
        result = self.login_protocol.login(username, password)
        self.assertTrue(result['success'])
        self.assertIsNotNone(result['session_key'])

    def test_login_failure(self):
        username = "alice"
        password = "wrong_password"
        result = self.login_protocol.login(username, password)
        self.assertFalse(result['success'])
        self.assertIsNone(result.get('session_key'))

    def test_login_nonexistent_user(self):
        username = "nonexistent_user"
        password = "password"
        result = self.login_protocol.login(username, password)
        self.assertFalse(result['success'])
        self.assertIsNone(result.get('session_key'))

if __name__ == '__main__':
    unittest.main()