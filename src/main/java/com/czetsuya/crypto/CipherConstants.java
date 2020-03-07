package com.czetsuya.crypto;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class CipherConstants {

	public static final String AES = "AES";
	public static final String CIPHER_TRANSFORMATION_GCM = "AES/GCM/NoPadding";
	public static final String CIPHER_TRANSFORMATION_CBC = "AES/CBC/PKCS5Padding";
	public static final int IV_LENGTH_BYTE = 12;
	public static final int TAG_LENGTH_BIT = 128;

	public static final String RSA = "RSA";
	public static final int RSA_KEY_SIZE = 8192;
	public static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";

	private CipherConstants() {

	}

}
