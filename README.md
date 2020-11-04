[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

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

1.) You must run App.java to generate both the AES key and RSA private and public keys.

2.) Refresh your project and key files should be generated in its root.

3.) Copy both the rsa_public and rsa_private into your src/test/resources directory.

4.) Run mvn clean test

## Repositories

 - https://github.com/crypto-util
 
## Authors

 * **Edward P. Legaspi** - *Java Architect* - [czetsuya](https://github.com/czetsuya)
