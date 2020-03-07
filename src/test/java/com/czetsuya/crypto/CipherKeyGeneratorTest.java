package com.czetsuya.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.czetsuya.crypto.utils.CipherKeyGenerator;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class CipherKeyGeneratorTest {

	/**
	 * Depends on Java implementation.
	 * 
	 * @throws KeyGenerationException
	 */
	@Test
	public void generateAESSecretKeyTest() throws KeyGenerationException {

		assertThrows(Exception.class, () -> {
			CipherKeyGenerator.generateAESSecretKey("secret_key");
		});
	}

	@Test
	public void generateAESSecretKeyFromMessageDigestTest() throws KeyGenerationException {
		assertNotNull(CipherKeyGenerator.generateAESSecretKeyFromMessageDigest("secret_key"));
	}
}