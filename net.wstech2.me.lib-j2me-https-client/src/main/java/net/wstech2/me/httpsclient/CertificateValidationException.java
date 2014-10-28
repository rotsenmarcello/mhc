/* Copyright 2014 WS/Tech² Informatica LTDA.
 *
 * MHC (ME HTTPS Client) - An alternative J2ME Https Client.
 * 
 * http://www.wstech2.net/mhc/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.wstech2.me.httpsclient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * Represents an exception thrown during the certificate validation process.
 * 
 * The list {@link #errors} is used to register the errors detected by the
 * validators.
 * 
 * See {@link CertificateErrorHandler} for additional details about the error
 *      types that can throw this exception.
 * 
 */
public class CertificateValidationException extends IOException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * A @see java.lang.List containing all errors occurred during the
	 * validation process.
	 */
	private List errors = new ArrayList();

	/**
	 * @param reason Exception message.
	 * @param errors See {@link #errors}.
	 */
	public CertificateValidationException(String reason, List errors) {
		super(reason);
		this.errors = errors;
	}

	/**
	 * See {@link #errors}.
	 * @return  {@link #errors}.
	 */
	public List getErrors() {
		return errors;
	}

	/**
	 * @param errors {@link #errors}.
	 */
	public void setErrors(List errors) {
		this.errors = errors;
	}

}
