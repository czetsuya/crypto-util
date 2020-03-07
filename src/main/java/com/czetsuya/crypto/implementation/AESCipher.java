package com.czetsuya.crypto.implementation;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.czetsuya.crypto.CipherConstants;
import com.czetsuya.crypto.DecryptionException;
import com.czetsuya.crypto.EncryptionException;
import com.czetsuya.crypto.utils.CipherUtil;

/**
 * A utility class that provides encryption and decryption functionality using
 * AES algorithm.
 * 
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public final class AESCipher {

	private static AESCipher instance = null;
	private ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();

	private AESCipher() {

	}

	public static AESCipher getInstance() {

		if (instance == null) {
			instance = new AESCipher();
		}

		return instance;
	}

	public Cipher getCipher() {

		Cipher cipher = cipherWrapper.get();
		if (cipher == null) {
			try {
				cipher = Cipher.getInstance(CipherConstants.CIPHER_TRANSFORMATION_GCM);

			} catch (Exception e) {
				throw new IllegalStateException("could not get cipher instance", e);
			}
			cipherWrapper.set(cipher);

			return cipherWrapper.get();

		} else {
			return cipher;
		}
	}

	/**
	 * Encrypts a plain text using a given secret with AES algorithm.
	 * 
	 * @param plainText the text to encrypt
	 * @param secretKey the secret use to encrypt the text
	 * @return the encrypted text
	 * @throws EncryptionException when encryption algorithm is not supported or
	 *                             encryption failed
	 */
	public String encrypt(String plainText, SecretKey secretKey) throws EncryptionException {

		byte[] encodedText = CipherUtil.encodeToBase64ByteArray(plainText);
		byte[] encryptedText = encrypt(encodedText, secretKey);

		return CipherUtil.printBase64ByteArray(encryptedText);
	}

	@Deprecated
	private byte[] encryptWithCBC(byte[] input, SecretKey secretKey) throws EncryptionException {

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(CipherConstants.CIPHER_TRANSFORMATION_CBC);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] encryptedText = cipher.doFinal(input);
			byte[] iv = cipher.getIV();

			return CipherUtil.concat(iv, encryptedText);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			throw new EncryptionException(e);
		}
	}

	private byte[] encrypt(byte[] input, SecretKey secretKey) throws EncryptionException {

		Cipher cipher;
		try {
			cipher = getCipher();
			byte[] iv = new byte[CipherConstants.IV_LENGTH_BYTE];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(iv);
			GCMParameterSpec parameterSpec = new GCMParameterSpec(CipherConstants.TAG_LENGTH_BIT, iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
			byte[] encryptedText = cipher.doFinal(input);

			return CipherUtil.concatGCM(iv, encryptedText);

		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
				| InvalidAlgorithmParameterException e) {
			throw new EncryptionException(e);
		}
	}

	/**
	 * Decrypts an encrypted text using a given secret with AES algorithm.
	 * 
	 * @param plainText the text to decrypt
	 * @param secretKey the secret use to decrypt the text
	 * @return the decrypted text
	 * @throws DecryptionException when decryption algorithm is not supported or
	 *                             decryption failed
	 */
	public String decrypt(String cipherText, SecretKey secretKey) throws DecryptionException {

		byte[] encryptedText = CipherUtil.parseBase64String(cipherText);
		byte[] encodedText = decrypt(encryptedText, secretKey);

		return CipherUtil.decodeToPlainString(encodedText);
	}

	@Deprecated
	private byte[] decryptWithCBC(byte[] encryptedData, SecretKey secretKey) throws DecryptionException {

		try {
			byte[][] splittedInput = CipherUtil.split(encryptedData, 16);
			byte[] iv = splittedInput[0];
			byte[] encryptedText = splittedInput[1];
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(CipherConstants.CIPHER_TRANSFORMATION_CBC);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

			return cipher.doFinal(encryptedText);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new DecryptionException(e);
		}
	}

	private byte[] decrypt(byte[] encryptedData, SecretKey secretKey) throws DecryptionException {

		try {
			ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
			int ivLength = byteBuffer.get();
			byte[] iv = new byte[ivLength];
			byteBuffer.get(iv);
			byte[] encryptedText = new byte[byteBuffer.remaining()];
			byteBuffer.get(encryptedText);

			Cipher cipher = getCipher();
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(CipherConstants.TAG_LENGTH_BIT, iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

			return cipher.doFinal(encryptedText);

		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new DecryptionException(e);
		}
	}
}
