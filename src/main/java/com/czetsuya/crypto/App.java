package com.czetsuya.crypto;

import com.czetsuya.crypto.utils.CipherKeyGenerator;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) {

		try {
			CipherKeyGenerator.generateAESSecretKeyInFile();
			CipherKeyGenerator.generateRsaKeyPair();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
