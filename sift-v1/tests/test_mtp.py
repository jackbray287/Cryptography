import unittest
from client.siftprotocols.mtp import MTP

class TestMTP(unittest.TestCase):
    
    def setUp(self):
        self.mtp = MTP()

    def test_message_format(self):
        # Test the message format for MTP
        message = self.mtp.create_message("test_command", "test_payload")
        self.assertEqual(len(message), expected_length)  # Replace expected_length with the actual expected length

    def test_encryption_decryption(self):
        # Test encryption and decryption functionality
        original_payload = "test_payload"
        encrypted_payload = self.mtp.encrypt(original_payload)
        decrypted_payload = self.mtp.decrypt(encrypted_payload)
        self.assertEqual(original_payload, decrypted_payload)

    def test_sequence_number_increment(self):
        # Test that the sequence number increments correctly
        initial_sequence = self.mtp.sequence_number
        self.mtp.send_message("test_command", "test_payload")
        self.assertEqual(self.mtp.sequence_number, initial_sequence + 1)

if __name__ == '__main__':
    unittest.main()