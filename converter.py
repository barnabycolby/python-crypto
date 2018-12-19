#! /usr/bin/env python3
import base64

"""
Converts between various python types in an easy to use way, without having to remember the specific Python syntax.
"""
class Converter:
    def __init__(self, the_input, input_type=None):
        # Detect the type and convert appropriately.
        if input_type == None and type(the_input) is str:
            self.underlying_bytes = the_input.encode("utf-8")
        elif input_type == "hex" and type(the_input) is str:
            self.underlying_bytes = bytearray.fromhex(the_input)
        elif input_type == "base64" and type(the_input) is str:
            self.underlying_bytes = base64.b64decode(the_input)
        elif type(the_input) is bytes:
            self.underlying_bytes = the_input
        else:
            raise Exception("I don't know how to deal with that type yet.")


    def hex(self):
        return self.underlying_bytes.hex()

    
    def bytes(self):
        return bytes(self.underlying_bytes)


    def base64(self):
        return base64.b64encode(self.underlying_bytes).decode("utf-8")


    def string(self):
        return self.underlying_bytes.decode("utf-8")


    def bits(self):
        bitstring = ""
        for byte in self.underlying_bytes:
            bitstring += bin(byte).lstrip("0b").zfill(8)
        return bitstring


if __name__ == "__main__":
    print("This is a library and should not be run directly.")
