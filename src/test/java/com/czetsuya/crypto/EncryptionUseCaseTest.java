package com.czetsuya.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.czetsuya.crypto.implementation.AESCipher;
import com.czetsuya.crypto.implementation.RSACipher;
import com.czetsuya.crypto.implementation.RawRSAKey;
import com.czetsuya.crypto.utils.CipherKeyGenerator;
import com.czetsuya.crypto.utils.CipherUtil;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class EncryptionUseCaseTest {

	private static String secretText = "yK9LpkLW6C9bmmZWTmhpU8bC";
	private static SecretKey secretKey;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;

	@BeforeAll
	public static void init() throws ClassNotFoundException, IOException, KeyGenerationException {

		secretKey = CipherKeyGenerator.generateAESSecretKeyFromMessageDigest("yK9LpkLW6C9bmmZWTmhpU8bC");

		RawRSAKey rawPublicKey = CipherUtil.readRSAKeyFromFile("src/test/resources/rsa_public");
		publicKey = CipherKeyGenerator.generateRSAPublicKey(rawPublicKey);

		RawRSAKey rawPrivateKey = CipherUtil.readRSAKeyFromFile("src/test/resources/rsa_private");
		privateKey = CipherKeyGenerator.generateRSAPrivateKey(rawPrivateKey);
	}

	/**
	 * RSA is more secure compared to AES but it's slower as well. In this test we
	 * will use the AES to encrypt the actual message and then encrypt the AES
	 * secret key using RSA. Ths source will have access to the RSA's public key
	 * while the receiving application will have the private key, this application
	 * must be secured.
	 * 
	 * @throws EncryptionException    when encryption fails
	 * @throws DecryptionException    when decryption fails
	 * @throws KeyGenerationException when key is not properly initialized
	 */
	@Test
	public void encryption_Workflow_Test_Ok() throws EncryptionException, DecryptionException, KeyGenerationException {

		// This normally happens on the terminal side where confidential information
		// such as payment is entered

		// encrypt the aes plain secret key using rsa
		String enryptedRsaKey = RSACipher.getInstance().encrypt(secretText, publicKey);

		String plainMessage = "Hello czetsuyatech!";
		// encrypt the message using the aes key
		String encryptedMessage = AESCipher.getInstance().encrypt(plainMessage, secretKey);

		RequestBody request = new RequestBody();
		request.setRsaKey(enryptedRsaKey);
		request.setMessage(encryptedMessage);

		// On the server side we need to decrypt the message using the private key

		// first we decrypt the aes key
		String decryptedAesKey = RSACipher.getInstance().decrypt(request.getRsaKey(), privateKey);

		// with the aes key we can now decrypt the message

		// initialize the aes secret key
		SecretKey decryptedSecretKey = CipherKeyGenerator.generateAESSecretKeyFromMessageDigest(decryptedAesKey);

		// decrypt the message using aes
		String decryptedMessage = AESCipher.getInstance().decrypt(request.getMessage(), decryptedSecretKey);

		assertEquals(plainMessage, decryptedMessage);
	}
}
