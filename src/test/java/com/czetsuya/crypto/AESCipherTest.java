package com.czetsuya.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.czetsuya.crypto.implementation.AESCipher;
import com.czetsuya.crypto.utils.CipherKeyGenerator;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class AESCipherTest {

	private static SecretKey secretKey;

	@BeforeAll
	public static void init() throws KeyGenerationException {
		secretKey = CipherKeyGenerator.generateAESSecretKeyFromMessageDigest("yK9LpkLW6C9bmmZWTmhpU8bC");
	}

	@ParameterizedTest
	@ValueSource(strings = { "czetsuyatech", "Hello World!", "378282246310005", "371449635398431", "378734493671000",
			"5610591081018250", "30569309025904", "38520000023237", "6011111111111117", "6011000990139424",
			"5555555555554444", "4111111111111111", "10-1984", "Oct 1984", })
	public void when_Encrypt_Decrypt_Ok(String input) throws EncryptionException, DecryptionException {

		String encryptedInput = AESCipher.getInstance().encrypt(input, secretKey);
		String decryptedInput = AESCipher.getInstance().decrypt(encryptedInput, secretKey);

		assertEquals(input, decryptedInput);
	}
}
