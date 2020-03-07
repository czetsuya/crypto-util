package com.czetsuya.crypto.utils;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

import com.czetsuya.crypto.implementation.RawRSAKey;

/**
 * Utility methods for encryption and decryption using RSA algorithm.
 * 
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public final class CipherUtil {

	private CipherUtil() {
		super();
	}

	public static byte[] encodeToBase64ByteArray(String plainString) {
		return Base64.encodeBase64(plainString.getBytes());
	}

	public static String decodeToPlainString(byte[] base64ByteArray) {
		return new String(Base64.decodeBase64(base64ByteArray));
	}

	public static byte[] parseBase64String(String base64String) {
		return DatatypeConverter.parseBase64Binary(base64String);
	}

	public static String printBase64ByteArray(byte[] base64ByteArray) {
		return DatatypeConverter.printBase64Binary(base64ByteArray);
	}

	public static RawRSAKey readRSAKeyFromFile(String pathToFile) throws IOException, ClassNotFoundException {

		try (FileInputStream fileInputStream = new FileInputStream(pathToFile)) {
			try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
				return (RawRSAKey) objectInputStream.readObject();
			}
		}
	}

	public static void writeRSAKeyToFile(RawRSAKey rsaKey, String pathToFile) throws IOException {

		try (FileOutputStream fileOutputStream = new FileOutputStream(pathToFile)) {
			try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
				objectOutputStream.writeObject(rsaKey);
			}
		}
	}

	public static byte[] concat(byte[] iv, byte[] encryptedText) throws IOException {

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byteArrayOutputStream.write(iv);
		byteArrayOutputStream.write(encryptedText);

		return byteArrayOutputStream.toByteArray();
	}

	public static byte[] concatGCM(byte[] iv, byte[] encryptedText) {

		ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encryptedText.length);
		byteBuffer.put((byte) iv.length);
		byteBuffer.put(iv);
		byteBuffer.put(encryptedText);

		return byteBuffer.array();
	}

	public static byte[][] split(byte[] input, int seperatorIndex) {

		byte[] firstInput = Arrays.copyOf(input, seperatorIndex);
		byte[] secondInput = Arrays.copyOfRange(input, seperatorIndex, input.length);
		byte[][] splittedInput = new byte[2][];
		splittedInput[0] = firstInput;
		splittedInput[1] = secondInput;

		return splittedInput;
	}

	public static void writeAESKeyToFile(SecretKey secretKey, String pathToFile) throws IOException {

		try (PrintWriter printWriter = new PrintWriter(pathToFile)) {
			writeAESKeyToFile(printWriter, "Key: %s", secretKey);
		}
	}

	private static void writeAESKeyToFile(PrintWriter printWriter, String label, SecretKey secretKey) {

		if (secretKey != null) {
			String encodedSecretKey = CipherUtil.printBase64ByteArray(secretKey.getEncoded());
			printWriter.format(label, encodedSecretKey);
			printWriter.println();
		}
	}
}
