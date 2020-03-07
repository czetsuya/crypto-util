package com.czetsuya.crypto;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class EncryptionException extends Exception {

	private static final long serialVersionUID = 2483624957598415842L;

	public EncryptionException() {
		super();
	}

	public EncryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public EncryptionException(String message, Throwable cause) {
		super(message, cause);
	}

	public EncryptionException(String message) {
		super(message);
	}

	public EncryptionException(Throwable cause) {
		super(cause);
	}

}
