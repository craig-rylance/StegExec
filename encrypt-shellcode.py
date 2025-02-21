import sys

if len(sys.argv) != 2:
    print("Error: shellcode not supplied to python script")
    sys.exit(1)

shellcode = sys.argv[1]

shellcode_bytes = [int(b, 16) for b in shellcode.split()]

key = "supersecretkey"
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

