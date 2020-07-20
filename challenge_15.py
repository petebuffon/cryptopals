"""PKCS#7 padding validation"""


def padding_validation(plaintext):
    # list of pad characters
    pad_chrs = ""
    for i in range(1, 17):
        pad_chrs += chr(i)
    # dictionary of proper padding strings
    pad_dict = {}
    for i in range(1, 17):
        pad_dict[i] = chr(i) * i
    text = ""
    padding = ""
    for c in plaintext:
        if c in pad_chrs:
            padding += c
        else:
            text += c
    # check for proper padding
    if len(text) < 16:
        if padding != chr(16 - len(text)) * (16 - len(text)):
            raise ValueError("Invalid PKCS#7 Padding")
    elif len(text) % 16 == 0:
        if padding != chr(16) * 16:
            raise ValueError("Invalid PKCS#7 Padding")
    else:
        if padding != chr(16 - len(text) % 16) * (16 - len(text) % 16):
            raise ValueError("Invalid PKCS#7 Padding")
    # strip padding
    return text


plaintext = "ICE ICE BABY\x04\x04\x04\x04"
# print(padding_validation(plaintext))
