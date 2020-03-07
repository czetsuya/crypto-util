package com.czetsuya.crypto.implementation;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.czetsuya.crypto.CipherConstants;
import com.czetsuya.crypto.DecryptionException;
import com.czetsuya.crypto.EncryptionException;
import com.czetsuya.crypto.utils.CipherUtil;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public final class RSACipher {

	private static RSACipher instance = null;
	private ThreadLocal<Cipher> cipherWrapper = new ThreadLocal<>();

	private RSACipher() {
		super();
	}

	public static RSACipher getInstance() {

		if (instance == null) {
			instance = new RSACipher();
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

	public String encrypt(String plainText, PublicKey publicKey) throws EncryptionException {

		try {
			byte[] encodedText = CipherUtil.encodeToBase64ByteArray(plainText);
			byte[] encryptedText = encrypt(encodedText, publicKey);

			return CipherUtil.printBase64ByteArray(encryptedText);

		} catch (Exception e) {
			throw new EncryptionException(e);
		}
	}

	private byte[] encrypt(byte[] input, PublicKey publicKey) throws EncryptionException {

		try {
			Cipher cipher = Cipher.getInstance(CipherConstants.RSA_ECB_PKCS1PADDING);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			return cipher.doFinal(input);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new EncryptionException(e);
		}
	}

	public String decrypt(String cipherText, PrivateKey privateKey) throws DecryptionException {

		try {
			byte[] encryptedText = CipherUtil.parseBase64String(cipherText);
			byte[] encodedText = decrypt(encryptedText, privateKey);

			return CipherUtil.decodeToPlainString(encodedText);

		} catch (Exception e) {
			throw new DecryptionException(e);
		}
	}

	private byte[] decrypt(byte[] input, PrivateKey privateKey) throws DecryptionException {

		try {
			Cipher cipher = Cipher.getInstance(CipherConstants.RSA_ECB_PKCS1PADDING);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			return cipher.doFinal(input);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			throw new DecryptionException(e);
		}
	}

}
