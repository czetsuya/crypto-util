*If you would like to support these tutorials, you can contribute to my [Patreon account](https://patreon.com/czetsuya)

# Crypto Utility Project

This project contains encryption and decryption utility classes that suppors both AES and RSA algorithm. 

A use case is provided in test that describes how a message is encrypted, passed and decrypted from the source or normally terminal application to the receiving or normally secured server side application.

## Features

 - AES key generation
 - AES encryption
 - AES decryption
 - RSA public / private key generation
 - RSA encryption
 - RSA decryption

## How this Project Works

1.) Run App.java to generate both the AES key and RSA private & public key files.

2.) The key files should be generated in the project root. Thus, refresh your project to make them visible.

3.) Copy both the rsa_public and rsa_private into your src/test/resources directory.

4.) Run mvn clean test
