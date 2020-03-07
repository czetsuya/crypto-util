package com.czetsuya.crypto.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import com.czetsuya.crypto.CipherConstants;
import com.czetsuya.crypto.KeyGenerationException;
import com.czetsuya.crypto.implementation.RawRSAKey;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public final class CipherKeyGenerator {

	private static final String RSA_PUBLIC = "rsa_public";
	private static final String RSA_PRIVATE = "rsa_private";

	private CipherKeyGenerator() {
		super();
	}

	public static void generateAESSecretKeyInFile() throws KeyGenerationException {

		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherConstants.AES);
			SecretKey rsaKey1 = keyGenerator.generateKey();

			CipherUtil.writeAESKeyToFile(rsaKey1, "rsa_key.txt");

		} catch (IOException | NoSuchAlgorithmException e) {
			throw new KeyGenerationException(e);
		}
	}

	/**
	 * Generates an AES secret key given a random raw string. SecretKeyFactory is
	 * platform specific, if it's not supported by your platform use
	 * {@link #generateAESSecretKeyFromMessageDigest(String)}
	 * 
	 * @param rawAESKey random key
	 * @return AES secret key
	 * @throws KeyGenerationException when key is not initialized or key factory not
	 *                                supported
	 */
	public static SecretKey generateAESSecretKey(String rawAESKey) throws KeyGenerationException {

		try {
			byte[] encodedRawAESKey = CipherUtil.parseBase64String(rawAESKey);
			SecretKeySpec secretKeySpec = new SecretKeySpec(encodedRawAESKey, CipherConstants.AES);
			SecretKeyFactory secretKeyGenerator = SecretKeyFactory.getInstance(CipherConstants.AES);
			return secretKeyGenerator.generateSecret(secretKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new KeyGenerationException(e);
		}
	}

	/**
	 * Generates an AES secret key given a random raw string.
	 * 
	 * @param rawAESKey random key
	 * @return AES secret key
	 * @throws KeyGenerationException when key is not initialized or key factory not
	 *                                supported
	 */
	public static SecretKey generateAESSecretKeyFromMessageDigest(String rawSecretKey) throws KeyGenerationException {

		byte[] key;
		MessageDigest sha = null;
		try {
			key = CipherUtil.parseBase64String(rawSecretKey);
			sha = MessageDigest.getInstance("SHA-256");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);

			return new SecretKeySpec(key, "AES");

		} catch (NoSuchAlgorithmException e) {
			throw new KeyGenerationException(e);
		}
	}

	public static void generateRsaKeyPair() throws KeyGenerationException {

		try {
			KeyPair keyPair = generateKeyPair();
			KeyFactory keyFactory = KeyFactory.getInstance(CipherConstants.RSA);
			RawRSAKey rsaPublicKey = generatePublicKey(keyPair, keyFactory);
			RawRSAKey rsaPrivateKey = generatePrivateKey(keyPair, keyFactory);
			CipherUtil.writeRSAKeyToFile(rsaPublicKey, RSA_PUBLIC);
			CipherUtil.writeRSAKeyToFile(rsaPrivateKey, RSA_PRIVATE);

		} catch (Exception e) {
			throw new KeyGenerationException(e);
		}
	}

	public static PublicKey generateRSAPublicKey(RawRSAKey rawRSAKey) throws KeyGenerationException {

		try {
			BigInteger modulus = rawRSAKey.getModulus();
			BigInteger publicExponent = rawRSAKey.getExponent();
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
			KeyFactory keyFactory = KeyFactory.getInstance(CipherConstants.RSA);

			return keyFactory.generatePublic(rsaPublicKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new KeyGenerationException(e);
		}
	}

	public static PrivateKey generateRSAPrivateKey(RawRSAKey rawRSAKey) throws KeyGenerationException {

		try {
			BigInteger modulus = rawRSAKey.getModulus();
			BigInteger privateExponent = rawRSAKey.getExponent();
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
			KeyFactory keyFactory = KeyFactory.getInstance(CipherConstants.RSA);

			return keyFactory.generatePrivate(rsaPrivateKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new KeyGenerationException(e);
		}
	}

	private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CipherConstants.RSA);
		keyPairGenerator.initialize(CipherConstants.RSA_KEY_SIZE);

		return keyPairGenerator.generateKeyPair();
	}

	private static RawRSAKey generatePublicKey(KeyPair keyPair, KeyFactory keyFactory) throws InvalidKeySpecException {

		PublicKey publicKey = keyPair.getPublic();
		RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
		BigInteger modulus = rsaPublicKeySpec.getModulus();
		BigInteger publicExponent = rsaPublicKeySpec.getPublicExponent();

		return new RawRSAKey(modulus, publicExponent);
	}

	private static RawRSAKey generatePrivateKey(KeyPair keyPair, KeyFactory keyFactory) throws InvalidKeySpecException {

		PrivateKey privateKey = keyPair.getPrivate();
		RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
		BigInteger modulus = rsaPrivateKeySpec.getModulus();
		BigInteger privateExponent = rsaPrivateKeySpec.getPrivateExponent();

		return new RawRSAKey(modulus, privateExponent);
	}

}
