# BouncyCastle.AesGcm
Implementation of AesGcm Encryption using Bouncy Castle library. 

This library uses streams for encryption and decryption instead of one big chunk of plain text. This can be very usefull if the contents is very big and we need to encrypt and decrypt the text on thy fly using a stream.

