"""Convert hex to base64."""
import base64

# Convert hex to bytes
ciphertext = bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f"
                           "6e6f7573206d757368726f6f6d")

# Encode bytes to base64
base64_string = base64.b64encode(ciphertext)
print(base64_string)
