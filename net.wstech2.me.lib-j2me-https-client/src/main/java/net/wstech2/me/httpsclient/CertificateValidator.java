/* Copyright 2014 WS/Tech² Informatica LTDA.
 * 
 * MHC (ME HTTPS Client) - An alternative J2ME Https Client.
 * 
 * http://www.wstech2.net/mhc/
 *
 * Based on Internet and Bouncy Castle samples
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
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import javax.microedition.rms.InvalidRecordIDException;
import javax.microedition.rms.RecordStoreException;
import javax.microedition.rms.RecordStoreNotOpenException;

import org.bouncycastle.cert.CertException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * 
 * Validates a certificate chain against a external keystore (either the record
 * store or a file embed in the application jar).
 * 
 * If {@link HttpsConnectionImpl#isAllowUntrustedCertificates()} is true then
 * this certificate validator will ignore almost all mismatching attributes
 * (validity, common name, signer , etc.). The only "always fatal" error is an
 * invalid certificate signature when validating against the issuer public key,
 * meaning the server certificate was modified in transit. However, it is
 * important to mention that if
 * {@link HttpsConnectionImpl#isAllowUntrustedCertificates()} is true and no
 * issuer certificate was provided, than the validation will still return "ok".
 * The above mentioned "fatal exception" will occur only if the issuer/signer
 * certificate is provided and the server certificate's signature can not
 * validated using it.
 * 
 */
public class CertificateValidator implements TlsAuthentication {

	private HttpsConnectionImpl httpsConnectionImplInstance = null;

	/**
	 * See {@link HttpsConnectionImpl}
	 * 
	 * @return {@link HttpsConnectionImpl}
	 */
	public HttpsConnectionImpl getHttpsConnectionImplInstance() {
		return httpsConnectionImplInstance;
	}

	/**
	 * See {@link HttpsConnectionImpl}
	 * 
	 * @param httpsConnectionImplInstance
	 *            {@link HttpsConnectionImpl}
	 */
	public void setHttpsConnectionImplInstance(
			HttpsConnectionImpl httpsConnectionImplInstance) {
		this.httpsConnectionImplInstance = httpsConnectionImplInstance;
	}

	/**
	 * Creates a new validator instance.
	 * 
	 * @param httpsConnectionImplInstance
	 *            the HttpsConnectionImpl instance owning the certificate to be
	 *            validated. See {@link HttpsConnectionImpl}.
	 * 
	 */
	public CertificateValidator(HttpsConnectionImpl httpsConnectionImplInstance) {
		this.httpsConnectionImplInstance = httpsConnectionImplInstance;
	}

	/**
	 * 
	 * Validates whether the certificate is valid and if it was signed by the
	 * corresponding issuer Certificate/Key.
	 * 
	 * @param cert
	 *            the certificate to be validated.
	 * @param issuerCert
	 *            the issuer (normally a C.A.) certificate corresponding to the
	 *            key used to sign the certificate indicated at the previous
	 *            parameter.
	 * @param errors
	 *            a list to be filled - if needed - with errors detected during
	 *            the validation process. See
	 *            {@link CertificateValidationException#setErrors(List)}.
	 * @throws CertException
	 * @throws OperatorCreationException
	 * @return True if the certificate signature, start and end dates are valid.
	 *         False otherwise.
	 * @throws IOException
	 * 
	 */
	protected boolean validateCertificate(
			org.bouncycastle.asn1.x509.Certificate cert,
			org.bouncycastle.asn1.x509.Certificate issuerCert, List errors)
			throws OperatorCreationException, CertException, IOException {
		boolean signatureOk = false;
		boolean startDateOk = false;
		boolean endDateOk = false;
		signatureOk = verifySignature(cert, issuerCert, errors);
		HttpsConnectionUtils.logDebug("Signature OK:[[" + signatureOk
				+ "]] for [["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ " tested with signer certificate [" 
				+ CertificateValidatorUtils.extractCommonName(issuerCert, true) + "]]");
		if (!signatureOk) { // invalid certificate signature is a fatal error
			throw new CertificateValidationException(
					"Invalid certificate signature  for [["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ " tested with signer certificate [" 
				+ CertificateValidatorUtils.extractCommonName(issuerCert, true) + "]]", errors);
		}
		startDateOk = verifyStartDate(cert, errors);
		HttpsConnectionUtils.logDebug("Start Date OK:[[" + startDateOk
				+ "]] for [["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ "[]]]");
		endDateOk = verifyEndDate(cert, errors);
		HttpsConnectionUtils.logDebug("End Date OK:[[" + endDateOk
				+ "]] for [["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ "[]]]");

		return startDateOk && endDateOk;
	}

	/**
	 * Validates the certificate signature (hash).
	 * 
	 * @param cert
	 *            The certificate to be validated.
	 * @param issuerCert
	 *            the issuer (normally a C.A.) certificate corresponding to the
	 *            key used to sign the certificate indicated at the previous
	 *            parameter.
	 * 
	 * @param errors
	 *            a list to be filled - if needed - with errors detected during
	 *            the validation process. See
	 *            {@link CertificateValidationException#setErrors(List)}.
	 * 
	 * @return True if the certificate signature is valid. False otherwise.
	 * @throws IOException
	 * @throws InvalidCipherTextException
	 * @throws CertException
	 * @throws OperatorCreationException
	 * 
	 */
	protected boolean verifySignature(
			org.bouncycastle.asn1.x509.Certificate cert,
			org.bouncycastle.asn1.x509.Certificate issuerCert, List errors)
			throws OperatorCreationException, CertException, IOException {
		return CertificateValidatorUtils.verifySignature(cert, issuerCert,
				errors);
	}

	/**
	 * 
	 * Validates if the certificate's "start date" is valid. By valid we mean
	 * that it is <= current date.
	 * 
	 * @param cert
	 *            The certificate to be validated.
	 * 
	 * @param errors
	 *            a list to be filled - if needed - with errors detected during
	 *            the validation process. See
	 *            {@link CertificateValidationException#setErrors(List)}.
	 * 
	 * @return true if the certificate's "start date" is less than or equal to
	 *         the current date. False otherwise.
	 * 
	 * 
	 */
	protected boolean verifyStartDate(
			org.bouncycastle.asn1.x509.Certificate cert, List errors) {
		boolean retval = false;
		Date startDate = CertificateValidatorUtils.getDateFromX509Time(cert
				.getStartDate());
		Date currentDate = new Date();
		if (startDate.getTime() <= currentDate.getTime()) {
			retval = true;
		} else {
			String error = "Invalid start date.";
			HttpsConnectionUtils.logError(error);
			errors.add(error);
		}
		return retval;
	}

	/**
	 * 
	 * Validates if the certificate's "end date" is valid. By valid we mean that
	 * it is greater than or equal to the current date.
	 * 
	 * @param cert
	 *            The certificate to be validated.
	 * 
	 * @param errors
	 *            a list to be filled - if needed - with errors detected during
	 *            the validation process. See
	 *            {@link CertificateValidationException#setErrors(List)}.
	 * 
	 * @return true if the certificate's "end date" is greater than or equal to
	 *         the current date. False otherwise.
	 * 
	 */
	protected boolean verifyEndDate(
			org.bouncycastle.asn1.x509.Certificate cert, List errors) {
		boolean retval = false;
		Date endDate = CertificateValidatorUtils.getDateFromX509Time(cert
				.getEndDate());
		Date currentDate = new Date();
		if (endDate.getTime() >= currentDate.getTime()) {
			retval = true;
		} else {
			String error = "Invalid end date.";
			HttpsConnectionUtils.logError(error);
			errors.add(error);
		}
		return retval;
	}

	/**
	 * 
	 * Validates if the certificate's common name matches the server's hostname
	 * used in the HTTPS connection.
	 * 
	 * @param serverCertificateInfo
	 *            The certificate to be validated.
	 * 
	 * @param errors
	 *            a list to be filled - if needed - with errors detected during
	 *            the validation process. See
	 *            {@link CertificateValidationException#setErrors(List)}.
	 * 
	 * @return True if the certificate's common name matches the server's
	 *         hostname. False otherwise.
	 */
	protected boolean verifyServerCertificateCommonName(
			Hashtable serverCertificateInfo, List errors) {

		HttpsConnectionUtils.logDebug("verifyServerCertificateCommonName");
		String connectedServerHostname = this.getHttpsConnectionImplInstance()
				.getHost();

		boolean commonNameOk = false;
		commonNameOk = CertificateValidatorUtils.certificateMatchesHostname(serverCertificateInfo, connectedServerHostname );
		if (!commonNameOk) {
			String msg = "The connection hostname ["
					+ connectedServerHostname
					+ "] does not match any of the certificate's possible name attributes [ +"
					+ serverCertificateInfo.get("alternativeNames") + "].";
			HttpsConnectionUtils.logError(msg);
			errors.add(msg);
		}
		return commonNameOk;
	}

	/**
	 * See
	 * {@link org.bouncycastle.crypto.tls.TlsAuthentication#notifyServerCertificate(Certificate)}
	 */
	public void notifyServerCertificate(Certificate serverCertificate)
			throws IOException {
		List errors = new ArrayList();
		this.httpsConnectionImplInstance.setCertificate(serverCertificate);
		org.bouncycastle.asn1.x509.Certificate[] certs = serverCertificate
				.getCertificateList();
		HttpsConnectionUtils.logDebug("Certificate chain size:[["
				+ certs.length + "]]");

		try {
			Hashtable certificateChain = CertificateValidatorUtils
					.getCertChainInfoMap(certs);
			Hashtable serverCertInfo = CertificateValidatorUtils
					.getServerCertificateInfo(certificateChain, this.getHttpsConnectionImplInstance().getHost());

			System.out.println("validateServerCertificatePurposeAndCommonName");
			validateServerCertificate(serverCertInfo, errors);

			System.out.println("validateCertificateChain");
			validateCertificateChain(serverCertInfo, certificateChain, errors);
		} catch (Exception e) {
			e.printStackTrace();
			HttpsConnectionUtils.logError("An exception occured.", e);
			throw new IOException(e.getMessage());
		}
	}

	/**
	 * 
	 * Validates the server common name and the certificate extended key usage
	 * attribute.
	 * 
	 * See {@link #verifyServerCertificateCommonName(Hashtable, List)}.
	 * 
	 * @throws CertificateValidationException
	 */
	protected void validateServerCertificate(Hashtable serverCertInfo,
			List errors) throws CertificateValidationException {
		if (serverCertInfo == null) {
			String error = "It was not possible to find a valid certificate for server authentication (OID=1.3.6.1.5.5.7.3.1).";
			HttpsConnectionUtils.logError(error);
			errors.add(error);

			throw new CertificateValidationException(
					"Server certificate not found.", errors);
		}
		boolean commonNameOk = verifyServerCertificateCommonName(
				serverCertInfo, errors);
		if (!commonNameOk
				&& this.getHttpsConnectionImplInstance()
						.isAllowUntrustedCertificates() == false) {
			throw new CertificateValidationException(
					"Server hostname does not match with the certificate.",
					errors);
		}
	}

	/**
	 * Validates all certificates at the server certificate chain.
	 * 
	 * See
	 * {@link #validateCertificate(org.bouncycastle.asn1.x509.Certificate, org.bouncycastle.asn1.x509.Certificate, List)
	 * .
	 */
	protected void validateCertificateChain(Hashtable serverCertInfo,
			Hashtable certificateChain, List errors)
			throws RecordStoreNotOpenException, InvalidRecordIDException,
			RecordStoreException, OperatorCreationException, CertException,
			IOException {
		Hashtable certificateInfo = serverCertInfo;
		while (certificateInfo != null) {
			HttpsConnectionUtils.logDebug("Processing validateCertificateChain() for certificate :[["
					+ certificateInfo.get("commonName") + "]]");
			org.bouncycastle.asn1.x509.Certificate certificate = (org.bouncycastle.asn1.x509.Certificate) certificateInfo
					.get("cert");
			String issuerName = (String) certificateInfo.get("issuerCN");
			Hashtable issuerCertificateInfo = (Hashtable) certificateChain
					.get(issuerName);

			boolean isIssuerTrusted = ((Boolean) issuerCertificateInfo
					.get("isTrusted")).booleanValue();
			org.bouncycastle.asn1.x509.Certificate issuerCert = (org.bouncycastle.asn1.x509.Certificate) issuerCertificateInfo
					.get("cert");
			if (issuerCert == null
					&& this.getHttpsConnectionImplInstance()
							.isAllowUntrustedCertificates() == false) { // the
																		// issuer
																		// certificate
																		// could
																		// not
																		// be
																		// found
				String error = "It was not possible to find the signer certificate ["
						+ (String) certificateInfo.get("issuerCN")
						+ " for ["
						+ certificateInfo.get("commonName") + "]";
				errors.add(error);
				throw new CertificateValidationException(
						"Invalid certificate ["
								+ certificateInfo.get("commonName") + "]",
						errors);
			} else if (issuerCert == null
					&& this.getHttpsConnectionImplInstance()
							.isAllowUntrustedCertificates()) {
				isIssuerTrusted = true;
			}

			boolean validationOK = this.validateCertificate(certificate,
					issuerCert, errors);
			if (!validationOK
					&& this.getHttpsConnectionImplInstance()
							.isAllowUntrustedCertificates() == false) {
				throw new CertificateValidationException("Invalid certificate["
						+ certificateInfo.get("commonName") + "]", errors);
			} else if (validationOK && isIssuerTrusted) {
				HttpsConnectionUtils.logDebug("Certificate ["
						+ certificateInfo.get("commonName")
						+ "] successfully validated.");
				return ;
			}
			if (Boolean.TRUE.equals(certificateInfo.get("isSelfSigned")) == true) {
				break;
			}
			certificateInfo = (Hashtable) certificateChain.get(issuerName);
		}
		throw new CertificateValidationException("Invalid certificate chain.",
				errors);
	}

	/**
	 * {@link org.bouncycastle.crypto.tls.TlsAuthentication#getClientCredentials(CertificateRequest)}
	 * 
	 * <BR>
	 * CLIENT AUTHENTICATION NOT SUPPORTED.
	 * 
	 */
	public TlsCredentials getClientCredentials(
			CertificateRequest certificateRequest) throws IOException {
		return null;
	}

}
