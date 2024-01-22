# HHE-protocol

This repository is coursework for Tampere University course Security Protocols: Helping Alice and Bob to Share Secrets.
This coursework is not fully tested and finished yet!


How to Run

Prerequisites:
Install the SEAL library from Microsoft: https://github.com/microsoft/SEAL
Install the PASTA library: https://github.com/IAIK/hybrid-HE-framework

Configuration:
Change the CMakeLists.txt file to match the installation paths of the SEAL and PASTA libraries on your system.

Build:
In the project's directory, open a terminal, and run the following commands:
cmake .
make

Run:
After successfully building the project, run the executable:
./protocols/mything

Additional Notes:
Ensure that all dependencies are correctly installed, and the necessary header and library paths are specified in the CMakeLists.txt file.
