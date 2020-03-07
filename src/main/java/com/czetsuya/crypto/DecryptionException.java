package com.czetsuya.crypto;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class DecryptionException extends Exception {

	private static final long serialVersionUID = 3078395419581500383L;

	public DecryptionException() {
		super();
	}

	public DecryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public DecryptionException(String message, Throwable cause) {
		super(message, cause);
	}

	public DecryptionException(String message) {
		super(message);
	}

	public DecryptionException(Throwable cause) {
		super(cause);
	}

}
