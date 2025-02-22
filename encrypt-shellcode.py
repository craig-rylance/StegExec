import sys

if len(sys.argv) != 3:
    print("Useage: python3 encrypt-shellcode.py [key] '[shellcode]'")
    print("Exiting...")
    sys.exit(1)

key = sys.argv[1]
shellcode = sys.argv[2]

shellcode_bytes = [int(b, 16) for b in shellcode.split()]

encrypted_shellcode = []

# XOR Encrypt Shellcode
for i in range(len(shellcode_bytes)):
    encrypted_shellcode.append(hex(shellcode_bytes[i] ^ ord(key[i % len(key)])))

# Remove '0x' from each byte and print encrypted shellcode to shellcode.bin
with open("shellcode.bin", "wb") as file:
    for b in encrypted_shellcode:
        b = b.replace("0x", "")  
        byte_value = bytes.fromhex(b.zfill(2)) 
        file.write(byte_value)  

