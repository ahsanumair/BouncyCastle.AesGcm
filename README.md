# BouncyCastle.AesGcm
Implementation of AesGcm Encryption using Bouncy Castle library. 

This little library uses streams for encryption and decryption instead of one big chunk of text that needs to be read in memory first. This can be very usefull if the content that needs to be encrpted or decrypted is very big and we need to encrypt and decrypted that in chunks on the fly using streaming mode which is memory efficient.


