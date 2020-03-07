package com.czetsuya.crypto;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
public class KeyGenerationException extends Exception {

	private static final long serialVersionUID = -7721709586853933370L;

	public KeyGenerationException() {
		super();
	}

	public KeyGenerationException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public KeyGenerationException(String message, Throwable cause) {
		super(message, cause);
	}

	public KeyGenerationException(String message) {
		super(message);
	}

	public KeyGenerationException(Throwable cause) {
		super(cause);
	}

}
