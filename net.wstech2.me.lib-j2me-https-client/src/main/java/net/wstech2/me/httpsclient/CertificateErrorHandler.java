/* Copyright 2011 WS/Tech² Informatica LTDA.
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

/**
 * 
 * Defines a callback method to be invoked when the certificate sent by the server
 * is classified as invalid, i.e.:
 * 
 * <BR>
 * - the public key correspondent to the C.A.'s PK used to sign the certificate
 * could not be found. See {@link #ERROR_CA_CERTIFICATE_NOT_FOUND};
 * 
 * <BR>
 * - the certificate's start or end dates are, respectively, after or before the
 * current date. See {@link #ERROR_INVALID_START_DATE} and
 * {@link #ERROR_INVALID_END_DATE};
 * 
 * <BR>
 * - the certificate's common name value does not match the server's host
 * name. See {@link #ERROR_INVALID_COMMON_NAME};
 * 
 * <BR>
 * - the certificate's extended key usage attribute does not contain the server authentication usage type.
 * See {@link #CERTIFICATE_INVALID_FOR_SERVER_AUTHENTICATION}.
 * 
 */
public interface CertificateErrorHandler {

	/**
	 * The Server certificate's common name and the server's hostname do not
	 * match.
	 */
	public static int ERROR_INVALID_COMMON_NAME = 1;

	/**
	 * Certificate's start date is invalid, i.e., after current date.
	 */
	public static int ERROR_INVALID_START_DATE = 2;

	/**
	 * Certificate's end date is invalid, i.e., before current date.
	 */
	public static int ERROR_INVALID_END_DATE = 4;

	/**
	 * It was not possible to find at the device repositories the C.A.
	 * certificate corresponding to the private key used to sign the server
	 * certificate.
	 * 
	 */
	public static int ERROR_CA_CERTIFICATE_NOT_FOUND = 8;

	/**
	 * OID "1.3.6.1.5.5.7.3.1" was not found among the certificate's extended
	 * key usage attributes. This OID is used to indicate that the certificate
	 * can be used for server authentication.
	 */
	public static int CERTIFICATE_INVALID_FOR_SERVER_AUTHENTICATION = 16;

	/**
	 * Continue even if the certificate has errors.
	 */
	public static int ON_ERROR_CONTINUE = 1;

	/**
	 * Abort the connection.
	 */
	public static int ON_ERROR_ABORT = 2;

	/**
	 * Try again to validate the certificate. Probably used after the handler
	 * added a certificate to the record store.
	 */
	public static int ON_ERROR_TRY_AGAIN = 3;

	/**
	 * 
	 * A callback method to be invoke if the certificate sent by the
	 * server is determined to be invalid.
	 * 
	 * @param cert
	 *            server's certificate.
	 * @param errors
	 *            an int array containing the IDs corresponding to all errors
	 *            encountered by certificate validators.
	 * @param httpsConnectionInstance
	 *            the https connection instance associated with the certificate.
	 * @param certificateValidatorInstance
	 *            the {@link CertificateValidator} instance which performed the
	 *            server certificate validation.
	 * 
	 * @return     - 1: continue even if the certificate contains errors;
	 * 
	 * <BR>
	 *         - 2: abort;
	 * 
	 * <BR>
	 *         - 3: try again.
	 */
	int onCertificateValidationError(
			org.bouncycastle.asn1.x509.Certificate cert, int[] errors,
			HttpsConnectionImpl httpsConnectionInstance,
			CertificateValidator certificateValidatorInstance);

}
