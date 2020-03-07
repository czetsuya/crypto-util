package com.czetsuya.crypto.implementation;

import java.io.Serializable;
import java.math.BigInteger;

import lombok.Getter;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
@Getter
public class RawRSAKey implements Serializable {

	private static final long serialVersionUID = 1L;

	private BigInteger modulus;
	private BigInteger exponent;

	public RawRSAKey(BigInteger modulus, BigInteger exponent) {
		this.modulus = modulus;
		this.exponent = exponent;
	}
}
