# SensitiveContent
A custom[-ish] combined implementation of Diffie-Hellman and a double ratchet using AES+HMAC to facilitate manual encrypted exchanges.
## Requirements
- To build, install .NET 10 SDK.
- To run, install .NET 10 Desktop Runtime.

Available at [.NET 10.0](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
## Expected common usage pipeline:
1. Run the program, which prompts for whether it should send messages first [only one out of two instances should send messages first], initialises a double ratchet, and prints instructions corresponding to each side.
1. If requested, retrieve the recipient's public key, paste into the window, and press Enter to initialise the cipher state.
1. Encrypt/Decrypt some text and/or a file using the shown options [if encrypting/decrypting a file, its path can be entered by dragging the file into the window]