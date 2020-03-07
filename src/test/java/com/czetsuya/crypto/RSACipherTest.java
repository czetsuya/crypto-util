package com.czetsuya.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.czetsuya.crypto.implementation.RSACipher;
import com.czetsuya.crypto.implementation.RawRSAKey;
import com.czetsuya.crypto.utils.CipherKeyGenerator;
import com.czetsuya.crypto.utils.CipherUtil;

public class RSACipherTest {

	private static PublicKey publicKey;
	private static PrivateKey privateKey;

	@BeforeAll
	public static void init() throws ClassNotFoundException, IOException, KeyGenerationException {

		RawRSAKey rawPublicKey = CipherUtil.readRSAKeyFromFile("src/test/resources/rsa_public");
		publicKey = CipherKeyGenerator.generateRSAPublicKey(rawPublicKey);

		RawRSAKey rawPrivateKey = CipherUtil.readRSAKeyFromFile("src/test/resources/rsa_private");
		privateKey = CipherKeyGenerator.generateRSAPrivateKey(rawPrivateKey);
	}

	@ParameterizedTest
	@ValueSource(strings = { "czetsuyatech", "Hello World!", "378282246310005", "371449635398431", "378734493671000",
			"5610591081018250", "30569309025904", "38520000023237", "6011111111111117", "6011000990139424",
			"5555555555554444", "4111111111111111", "10-1984", "Oct 1984", })
	public void shouldEncryptDecrypt(String input) throws EncryptionException, DecryptionException {

		String encryptedInput = RSACipher.getInstance().encrypt(input, publicKey);
		String decryptedInput = RSACipher.getInstance().decrypt(encryptedInput, privateKey);

		assertEquals(input, decryptedInput);
	}

}
