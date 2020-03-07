package com.czetsuya.crypto;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author Edward P. Legaspi | czetsuya@gmail.com
 */
@Data
@NoArgsConstructor
public class RequestBody {

	private String rsaKey;
	private String message;
}
