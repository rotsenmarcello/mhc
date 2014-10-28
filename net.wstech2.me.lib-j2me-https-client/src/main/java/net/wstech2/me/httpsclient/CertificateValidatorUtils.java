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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.microedition.rms.InvalidRecordIDException;
import javax.microedition.rms.RecordStoreException;
import javax.microedition.rms.RecordStoreNotOpenException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * 
 * A collection of static, state independent, auxiliary methods to support the
 * execution of common tasks.
 * 
 */

public class CertificateValidatorUtils {

	public static String SHA1_OID = "1.2.840.113549.1.1.5";
	public static String COMMON_NAME_OID = "2.5.4.3";

	/**
	 * @link http://www.alvestrand.no/objectid/2.5.29.37.html
	 */
	public static String EXTENDED_KEY_USAGE_OID = "2.5.29.37";

	/**
	 * @link http://www.alvestrand.no/objectid/2.5.29.15.html
	 */
	public static String KEY_USAGE_EXTENSION_OID = "2.5.29.15";

	public static String SERVER_AUTHENTICATION_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.1";

	/**
	 * 
	 * Prints common certificate informations like signature, signature
	 * algorithm, subject and issuer details, etc.
	 * 
	 * @param cert
	 *            The X509CertificateStructure containing the information that
	 *            will be printed.
	 * 
	 */
	public static void printCertificateDetails(
			org.bouncycastle.asn1.x509.Certificate cert) {

		HttpsConnectionUtils.logDebug("BEGIN CERTIFICATE DUMP FOR:[["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ "]]");

		HttpsConnectionUtils.logDebug("Certificate Signature:[["
				+ cert.getSignature().toString() + "]]");

		HttpsConnectionUtils.logDebug("Certificate Signature Algorithm OID:[["
				+ cert.getSignatureAlgorithm().getAlgorithm() + "]]");

		HttpsConnectionUtils.logDebug("Certificate Subject Info:[["
				+ cert.getSubject().toString() + "]]");

		HttpsConnectionUtils.logDebug("Certificate Subject common name (CN):[["
				+ extractCommonName(cert, false) + "]]");
		HttpsConnectionUtils
				.logDebug("Certificate Subject short common name (CN):[["
						+ extractCommonName(cert, true) + "]]");

		HttpsConnectionUtils.logDebug("Certificate Issuer Info:[["
				+ cert.getIssuer() + "]]");

		HttpsConnectionUtils.logDebug("Certificate Start Date:[["
				+ cert.getStartDate().getTime() + "]]");

		HttpsConnectionUtils.logDebug("Certificate End Date:[["
				+ cert.getEndDate().getTime() + "]]");

		HttpsConnectionUtils.logDebug("Certificate ASN.1 Dump:[["
				+ ASN1Dump.dumpAsString(cert, true) + "]]");

		HttpsConnectionUtils.logDebug("END CERTIFICATE DUMP FOR:[["
				+ CertificateValidatorUtils.extractCommonName(cert, true)
				+ "]]");
	}

	/**
	 * 
	 * Inspected and display various informations from the Certificate passed as
	 * parameter. Keys are presented in HEX values and ASN1 structures dumped
	 * using ASN1Dump.dumpAsString.
	 * 
	 * This method is intended for debug purposes only.
	 * 
	 * 
	 * @param cert
	 *            The X509CertificateStructure to be inspected.
	 * 
	 */
	public static void dumpCertificateInfo(
			org.bouncycastle.asn1.x509.Certificate cert) {
		boolean valid = false;
		TBSCertificate tbs = cert.getTBSCertificate();
		RSAEngine engine = new RSAEngine();
		SHA1Digest digest = new SHA1Digest();

		GenericSigner signer = new GenericSigner((engine), digest);
		RSAPublicKey signingKey;
		try {
			signingKey = RSAPublicKey.getInstance(cert
					.getSubjectPublicKeyInfo().parsePublicKey());

			HttpsConnectionUtils.logDebug("Public Key:[["
					+ cert.getSubjectPublicKeyInfo().parsePublicKey() + "]]");

			RSAKeyParameters keySpec = new RSAKeyParameters(false,
					signingKey.getModulus(), signingKey.getPublicExponent());
			signer.init(false, keySpec);
			HttpsConnectionUtils.logDebug("TBS DER object:[["
					+ tbs.getEncoded("DER") + "]]");

			signer.update(tbs.getEncoded(), 0, tbs.getEncoded().length);

			valid = signer.verifySignature(cert.getSignature().getBytes());

			HttpsConnectionUtils.logDebug("signer.verifySignature:[[" + valid
					+ "]]");

			SHA1Digest d2 = new SHA1Digest();
			d2.update(tbs.getEncoded("DER"), 0, tbs.getEncoded("DER").length);
			byte[] hash = new byte[d2.getDigestSize()];
			d2.doFinal(hash, 0);
			HttpsConnectionUtils.logDebug("tbs.getDEREncoded() HASH:[["
					+ new String(Hex.encode(hash)) + "]]");
			DEROctetString asn1Hash = new DEROctetString(hash);
			HttpsConnectionUtils
					.logDebug("ASN1 DEROctetString hash:[["
							+ new String(Hex.encode(asn1Hash.getEncoded("DER")))
							+ "]]");

			d2 = new SHA1Digest();
			d2.update(cert.getEncoded(), 0, cert.getEncoded().length);
			hash = new byte[d2.getDigestSize()];
			d2.doFinal(hash, 0);
			HttpsConnectionUtils.logDebug("cert.getEncoded() HASH:[["
					+ new String(Hex.encode(hash)) + "]]");

			byte[] signature = cert.getSignature().getBytes();
			HttpsConnectionUtils.logDebug("cert.getSignature().getBytes():[["
					+ new String(Hex.encode(signature)) + "]]");

			PKCS1Encoding engine2 = new PKCS1Encoding(new RSAEngine());
			engine2.init(false, keySpec);
			byte[] decryptedHash = engine2.processBlock(signature, 0,
					signature.length);
			HttpsConnectionUtils.logDebug("decryptedHash:[["
					+ new String(Hex.encode(decryptedHash)) + "]]");

			ASN1Object o = ASN1Primitive.fromByteArray(decryptedHash);
			HttpsConnectionUtils.logDebug("decryptedHash.getDEREncoded():[["
					+ new String(Hex.encode(o.getEncoded("DER"))) + "]]");

			HttpsConnectionUtils
					.logDebug("ASN1Dump.dumpAsString(decryptedHash,true):[["
							+ ASN1Dump.dumpAsString(o, true) + "]]");

			HttpsConnectionUtils.logDebug("engine.getInputBlockSize():[["
					+ engine2.getInputBlockSize() + "]]");

			HttpsConnectionUtils.logDebug("engine.getOutputBlockSize():[["
					+ engine2.getOutputBlockSize() + "]]");

			ASN1Sequence asn1SignSeq = (ASN1Sequence) ASN1Sequence
					.fromByteArray(decryptedHash);
			HttpsConnectionUtils.logDebug("Signature ASN1 Sequence:[["
					+ ASN1Dump.dumpAsString(asn1SignSeq, true) + "]]");

			AlgorithmIdentifier algorithm = AlgorithmIdentifier
					.getInstance(asn1SignSeq.getObjectAt(0));
			HttpsConnectionUtils.logDebug("AlgorithmIdentifier:[["
					+ ASN1Dump.dumpAsString(algorithm, true) + "]]");

			DEROctetString signedHash = (DEROctetString) DEROctetString
					.getInstance(asn1SignSeq.getObjectAt(1));
			HttpsConnectionUtils.logDebug("signedHash:[["
					+ ASN1Dump.dumpAsString(signedHash, true) + "]]");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 
	 * Obtains the digest instance corresponding to the Signature Algorithm OID
	 * stored within the X509CertificateStructure @cert parameter.
	 * 
	 * @param cert
	 *            The X509CertificateStructure to be analyzed.
	 * 
	 * @return A Digest (SHA1Digest, MD5Digest, etc.) instance. Null if no
	 *         digest corresponding to the OID could be found.
	 */

	public static ExtendedDigest getDigestInstance(
			org.bouncycastle.asn1.x509.Certificate cert) {
		String digestId = cert.getSignatureAlgorithm().getAlgorithm()
				.toString();
		if (digestId.equalsIgnoreCase(SHA1_OID)) {
			return new SHA1Digest();
		}
		return null;
	}

	/**
	 * Receives an org.bouncycastle.asn1.x509.Time returning a java.util.Date
	 * instance corresponding to the same timestamp as the
	 * org.bouncycastle.asn1.x509.Time informed.
	 * 
	 * @param time
	 *            An instance of org.bouncycastle.asn1.x509.Time containing a
	 *            given Date.
	 * 
	 * @return An instance of java.util.Date representing the same timestamp
	 *         from time.
	 */
	public static Date getDateFromX509Time(Time time) {
		Calendar retval = Calendar.getInstance();

		String timeString = time.getTime();

		Integer year = Integer.valueOf(timeString.substring(0, 4));
		Integer month = Integer.valueOf(timeString.substring(4, 6));
		Integer day = Integer.valueOf(timeString.substring(6, 8));
		Integer hour = Integer.valueOf(timeString.substring(8, 10));
		Integer minute = Integer.valueOf(timeString.substring(10, 12));
		Integer second = Integer.valueOf(timeString.substring(12, 14));

		retval.set(Calendar.YEAR, year.intValue());
		retval.set(Calendar.MONTH, month.intValue() - 1);
		retval.set(Calendar.DAY_OF_MONTH, day.intValue());
		retval.set(Calendar.HOUR_OF_DAY, hour.intValue());
		retval.set(Calendar.MINUTE, minute.intValue());
		retval.set(Calendar.SECOND, second.intValue());

		return retval.getTime();
	}

	/**
	 * Extracts and returns a java.lang.String corresponding to the common name
	 * of the subject from the certificate cert.
	 * 
	 * @param cert
	 *            The certificate from which the subject's common name is to be
	 *            extracted.
	 * 
	 * @return A string corresponding to the certificate subject's common name.
	 */
	public static String extractCommonName(
			org.bouncycastle.asn1.x509.Certificate cert, boolean shortCN) {
		if (shortCN) {

			RDN[] values = cert.getSubject().getRDNs(BCStyle.CN);
			if (values == null || values.length == 0)
				return null;
			return HttpsConnectionUtils.replace(
					values[0].getFirst().getValue().toString(),
					"\\,", ",");
		} else {
			return HttpsConnectionUtils.replace(
					cert.getSubject().toString(),
					"\\,", ",");
		}
	}

	/**
	 * Retrieves the issuer common name.
	 * 
	 * @param cert
	 *            The certificate from which the issuer name is to the
	 *            extracted.
	 * @return The issuer common name.
	 */
	public static String extractIssuerName(
			org.bouncycastle.asn1.x509.Certificate cert) {
		return HttpsConnectionUtils.replace(
				cert.getIssuer().toString(),
				"\\,", ",");
	}

	/**
	 * Retrieves the list of alternative DNS names for this certificate, if any.
	 * 
	 * @param cert
	 *            The certificate from which the issuer name is to the
	 *            extracted.
	 * @return A list with all alternative DNS names included in the
	 *         certificate.
	 * @throws IOException
	 */
	public static List extractSubjectAlternativeNameList(
			org.bouncycastle.asn1.x509.Certificate cert) throws IOException {
		List dnsNames = new ArrayList();
		dnsNames.add(CertificateValidatorUtils.extractCommonName(cert, true));
		Extension subjectAlternativeName = cert.getTBSCertificate()
				.getExtensions().getExtension(Extension.subjectAlternativeName);
		if (subjectAlternativeName == null) {
			return dnsNames;
		}
		ASN1OctetString oct = subjectAlternativeName.getExtnValue();
		ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(
				oct.getOctets()));
		GeneralNames gn = GeneralNames.getInstance(extIn.readObject());
		extIn.close();
		ASN1Sequence sq = (ASN1Sequence) gn.toASN1Primitive();
		for (int i = 0; i != sq.size(); i++) {
			GeneralName n = GeneralName.getInstance(sq.getObjectAt(i));
			dnsNames.add(n.getName().toString());

		}
		return dnsNames;
	}

	/**
	 * Creates a Hashtable containing information (common name, issuer cn,
	 * purpose, etc.) about all chain certificates.
	 * 
	 * @param certs
	 *            Certificates to be processed.
	 * @return a Hashtable containing information about all certificates ordered
	 *         by common name.
	 * @throws IOException
	 * @throws CertException
	 * @throws OperatorCreationException
	 * @throws RecordStoreException
	 * @throws InvalidRecordIDException
	 * @throws RecordStoreNotOpenException
	 */
	public static Hashtable getCertChainInfoMap(
			org.bouncycastle.asn1.x509.Certificate[] certs) throws IOException,
			OperatorCreationException, CertException,
			RecordStoreNotOpenException, InvalidRecordIDException,
			RecordStoreException {
		Hashtable certInfos = new Hashtable();
		Boolean hasHostAunthenticationCertificate = Boolean.FALSE;
		for (int i = 0; i < certs.length; i++) {
			org.bouncycastle.asn1.x509.Certificate cert = certs[i];
			CertificateValidatorUtils.printCertificateDetails(cert);

			String fullCommonName = CertificateValidatorUtils
					.extractCommonName(cert, false);
			Hashtable certInfo = (Hashtable) certInfos.get(fullCommonName);
			if (certInfo == null) {
				certInfo = new Hashtable();
				certInfos.put(fullCommonName, certInfo);
			}
			String issuerFullCommonName = CertificateValidatorUtils
					.extractIssuerName(cert);
			boolean isSelfSigned = CertificateValidatorUtils.verifySignature(
					cert, cert, new ArrayList());
			certInfo.put("isSelfSigned", isSelfSigned?Boolean.TRUE:Boolean.FALSE);
			if (isSelfSigned) {
				HttpsConnectionUtils.logDebug("Certificate [" + fullCommonName
						+ "] is self signed.");
				issuerFullCommonName = fullCommonName;
			}
			Hashtable issuerCertInfo = (Hashtable) certInfos
					.get(issuerFullCommonName);
			if (issuerCertInfo == null) {
				issuerCertInfo = new Hashtable();
				certInfos.put(issuerFullCommonName, issuerCertInfo);
				issuerCertInfo.put("fullCommonName", issuerFullCommonName);
				issuerCertInfo.put("isTrusted", Boolean.FALSE);
			}

			certInfo.put("parent", issuerFullCommonName);
			certInfo.put("cert", cert);
			issuerCertInfo.put("child", fullCommonName);
			issuerCertInfo.put("isIssuer", Boolean.TRUE);

			issuerCertInfo.put("isHostAunthenticationCertificate",
					Boolean.FALSE);
			Boolean isHostAunthenticationCertificate = CertificateValidatorUtils
					.isHostAunthenticationCertificate(cert);
			certInfo.put("isHostAunthenticationCertificate",
					isHostAunthenticationCertificate);
			hasHostAunthenticationCertificate = 
					hasHostAunthenticationCertificate.booleanValue()
							|| isHostAunthenticationCertificate.booleanValue()?Boolean.TRUE:Boolean.FALSE;
			String friendlyCommonName = CertificateValidatorUtils
					.extractCommonName(cert, true);
			certInfo.put("commonName", friendlyCommonName);
			certInfo.put("fullCommonName", fullCommonName);
			certInfo.put("alternativeNames",
					extractSubjectAlternativeNameList(cert));
			certInfo.put("issuerCN", issuerFullCommonName);
			certInfo.put(
					"isTrusted",
					isTrustedCertificate(cert, fullCommonName,
							friendlyCommonName));
		}
		if (hasHostAunthenticationCertificate.equals(Boolean.FALSE)) {
			// try the chain's first certificate
			Hashtable certInfo = (Hashtable) certInfos.elements().nextElement();
			certInfo.put("isHostAunthenticationCertificate", Boolean.TRUE);
		}
		loadIssuerRepositoryCertificatesIfAny(certInfos);
		HttpsConnectionUtils.printSep();
		HttpsConnectionUtils.logDebug("Certificate Chain[[\n"
				+ HttpsConnectionUtils.replace(certInfos.toString(), "}", "}\n") + "]]\n");
		HttpsConnectionUtils.printSep();
		return certInfos;
	}
	
	
	

	private static void loadIssuerRepositoryCertificatesIfAny(
			Hashtable certInfos) throws RecordStoreNotOpenException,
			InvalidRecordIDException, RecordStoreException, IOException {
		for (Enumeration e = certInfos.elements(); e.hasMoreElements();) {
			Hashtable certInfo = (Hashtable) e.nextElement();
			if (certInfo.get("cert") == null
					&& Boolean.TRUE.equals(certInfo.get("isIssuer"))) {
				Certificate repositoryCertificate = getCertificateFromJarOrRecordStore(
						(String) certInfo.get("fullCommonName"), 
						(String) certInfo.get("commonName")
						);
				if (repositoryCertificate == null) {
					continue;
				}
				certInfo.put("cert", repositoryCertificate);
				String commonName = extractCommonName(repositoryCertificate,
						true);
				if (commonName != null) {
					certInfo.put("commonName", commonName);
				}
				certInfo.put("isTrusted", Boolean.TRUE);
				certInfo.put("isHostAunthenticationCertificate", Boolean.FALSE);
				certInfo.put(
						"alternativeNames",
						extractSubjectAlternativeNameList(repositoryCertificate));
			}

		}
	}

	private static Boolean isTrustedCertificate(Certificate cert,
			String fullCommonName, String friendlyCommonName)
			throws RecordStoreNotOpenException, InvalidRecordIDException,
			RecordStoreException, IOException {
		Certificate repositoryCertificate = getCertificateFromJarOrRecordStore(
				fullCommonName, friendlyCommonName);
		if (repositoryCertificate == null) {
			HttpsConnectionUtils
					.logDebug("A file for [["
							+ fullCommonName
							+ "/"
							+ friendlyCommonName
							+ "]] was not located as a resource in the local repository.");
			return Boolean.FALSE;
		}
		boolean certificatesMatch = Arrays
				.constantTimeAreEqual(cert.getEncoded("DER"),
						repositoryCertificate.getEncoded("DER"));
		if (certificatesMatch) {
			HttpsConnectionUtils
					.logDebug("A file for [["
							+ fullCommonName
							+ "/"
							+ friendlyCommonName
							+ "]] was located as a resource in the local repository and "
							+ "the certificate will be considered as TRUSTED.");

		} else {
			HttpsConnectionUtils
					.logDebug("A file for [["
							+ fullCommonName
							+ "/"
							+ friendlyCommonName
							+ "]] was located as a resource in the local repository, but it DOES NOT"
							+ "MATCH the certificate sent by the client. It will NOT be considered as TRUESTED.");
			HttpsConnectionUtils.logDebug("Base 64 for[[" + fullCommonName
					+ "/" + friendlyCommonName + "]] sent by the client: \n"
					+ Base64.toBase64String(cert.getEncoded("DER")));
			HttpsConnectionUtils.logDebug("Base 64 for[["
					+ fullCommonName
					+ "/"
					+ friendlyCommonName
					+ "]] from the local repository:\n"
					+ Base64.toBase64String(repositoryCertificate
							.getEncoded("DER")));
		}
		return certificatesMatch?Boolean.TRUE:Boolean.FALSE;
	}

	private static Boolean isHostAunthenticationCertificate(Certificate cert)
			throws IOException {

		Extension extKeyUsageExtension = cert.getTBSCertificate()
				.getExtensions().getExtension(Extension.extendedKeyUsage);
		if (extKeyUsageExtension == null) {
			return Boolean.FALSE;
		}
		ASN1OctetString oct = extKeyUsageExtension.getExtnValue();
		ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(
				oct.getOctets()));
		ExtendedKeyUsage extKeyUsages = ExtendedKeyUsage.getInstance(extIn
				.readObject());
		extIn.close();
		KeyPurposeId[] keyPurposeIds = extKeyUsages.getUsages();
		for (int i = 0; i < keyPurposeIds.length; i++) {
			if (keyPurposeIds[i].equals(KeyPurposeId.id_kp_serverAuth)) {
				return Boolean.TRUE;
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Get the certificate info hashtable corresponding to the server
	 * certificate. Not the C.A. certificates, if any.
	 * 
	 * @param certInfos
	 *            The same hashtable generated by
	 *            {@link #getCertChainInfoMap(Certificate[])}.
	 * @param host
	 * @return Server certificate Hashtable info.
	 */
	public static Hashtable getServerCertificateInfo(Hashtable certInfos,
			String connectedServerHostname) {
		for (Enumeration e = certInfos.elements(); e.hasMoreElements();) {
			Hashtable certInfo = (Hashtable) e.nextElement();
			if (certificateMatchesHostname(certInfo, connectedServerHostname)) {
				HttpsConnectionUtils.logDebug("Server Certificate [["
						+ certInfo + "]].");
				return certInfo;
			}
		}
		for (Enumeration e = certInfos.elements(); e.hasMoreElements();) {
			Hashtable certInfo = (Hashtable) e.nextElement();
			if (Boolean.TRUE.equals(certInfo
					.get("isHostAunthenticationCertificate"))) {
				HttpsConnectionUtils.logDebug("Server Certificate [["
						+ certInfo + "]].");
				return certInfo;
			}
		}
		return null;
	}

	public static boolean certificateMatchesHostname(Hashtable certInfo,
			String connectedServerHostname) {
		if (certInfo.get("alternativeNames") == null) {
			return false;
		}
		boolean commonNameOk = false;
		for (int i = 0; i < ((List) certInfo.get("alternativeNames")).size()
				&& commonNameOk == false; i++) {
			String cn = (String) ((List) certInfo.get("alternativeNames"))
					.get(i);

			if (cn.indexOf('*') != -1) {
				commonNameOk = connectedServerHostname.endsWith(cn.substring(cn
						.indexOf('*') + 1));
			} else {
				commonNameOk = cn.trim().equalsIgnoreCase(
						connectedServerHostname);
			}
		}
		return commonNameOk;
	}

	/**
	 * Loads a certificate either from the device record store or from the
	 * application jar.
	 * 
	 * @param fullCN
	 *            The common name attribute identifying the certificate, like
	 *            "CN = j2metest.local,O = j2me-teste-org,L = Curitiba,ST = PR,C = BR"
	 *            .
	 * @param friendlyCN
	 *            the friendly common name, like j2metest.local.
	 * @return An instance of org.bouncycastle.asn1.x509.Certificate
	 *         corresponding to the certificate loaded or null if a certificate
	 *         was not found.
	 * @throws RecordStoreNotOpenException
	 * @throws InvalidRecordIDException
	 * @throws RecordStoreException
	 * @throws IOException
	 */
	public static org.bouncycastle.asn1.x509.Certificate getCertificateFromJarOrRecordStore(
			String fullCN, String friendlyCN)
			throws RecordStoreNotOpenException, InvalidRecordIDException,
			RecordStoreException, IOException {
		Certificate cert = null;
		byte[] certBA = loadJarResource("/res/certs/" + fullCN + ".der");
		if (certBA == null) {
			if(friendlyCN ==null){
				friendlyCN = getFriendlyCNFromFullSubjectName(fullCN);
			}
			certBA = loadJarResource("/res/certs/" + friendlyCN + ".der");
		}
		if (certBA != null && certBA.length != 0) {
			cert = Certificate.getInstance(certBA);
		}
		return cert;
	}

	private static String getFriendlyCNFromFullSubjectName(String fullCN) {
		Vector parts = HttpsConnectionUtils.split(fullCN,",");
		for(int i=0;parts != null && i<parts.size();i++){
			String p = (String) parts.elementAt(i);
			if(p.trim().toLowerCase().startsWith("cn=")
					||p.trim().toLowerCase().startsWith("cn =")){
				int pos = p.indexOf('=');
				return p.substring(pos+1).trim();
			}
		}
		
		return fullCN;
	}

	/**
	 * Loads a file from the application jar.
	 * 
	 * @param filename
	 *            The fullpath of the resource at the jar file.
	 * @return A byte array containing the file loaded.
	 * @throws IOException
	 */
	public static byte[] loadJarResource(String filename) throws IOException {
		InputStream is = CertificateValidatorUtils.class
				.getResourceAsStream(filename);
		if (is == null) {
			return null;
		}
		ByteArrayOutputStream file = new ByteArrayOutputStream();
		int b;
		while ((b = is.read()) != -1) {
			file.write(b);
		}
		return file.toByteArray();
	}

	public static boolean isAlgIdEqual(AlgorithmIdentifier id1,
			AlgorithmIdentifier id2) {
		if (!id1.getAlgorithm().equals(id2.getAlgorithm())) {
			return false;
		}

		if (id1.getParameters() == null) {
			if (id2.getParameters() != null
					&& !id2.getParameters().equals(DERNull.INSTANCE)) {
				return false;
			}

			return true;
		}

		if (id2.getParameters() == null) {
			if (id1.getParameters() != null
					&& !id1.getParameters().equals(DERNull.INSTANCE)) {
				return false;
			}

			return true;
		}

		return id1.getParameters().equals(id2.getParameters());
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
	public static boolean verifySignature(
			org.bouncycastle.asn1.x509.Certificate cert,
			org.bouncycastle.asn1.x509.Certificate issuerCert, List errors)
			throws OperatorCreationException, CertException, IOException {
		boolean retval = false;
		if (!CertificateValidatorUtils.isAlgIdEqual(cert.getTBSCertificate()
				.getSignature(), cert.getSignatureAlgorithm())) {
			throw new CertException(
					"signature invalid - algorithm identifier mismatch");
		}

		ContentVerifierProvider verifierProvider = new BcRSAContentVerifierProviderBuilder(
				new DefaultDigestAlgorithmIdentifierFinder())
				.build(PublicKeyFactory.createKey(issuerCert
						.getTBSCertificate().getSubjectPublicKeyInfo()));
		ContentVerifier verifier;
		try {
			verifier = verifierProvider.get((cert.getTBSCertificate()
					.getSignature()));

			OutputStream sOut = verifier.getOutputStream();
			DEROutputStream dOut = new DEROutputStream(sOut);

			dOut.writeObject(cert.getTBSCertificate());

			sOut.close();
		} catch (Exception e) {
			throw new CertException("unable to process signature: "
					+ e.getMessage(), e);
		}

		retval = verifier.verify(cert.getSignature().getBytes());

		if (retval == false) {
			String error = "Invalid certificate signature for [["
					+ extractCommonName(cert, true)
					+ "]] validated against the Signer Certificate [["
					+ extractCommonName(issuerCert, true) + "]].";
			HttpsConnectionUtils.logError(error);
			errors.add(error);
		}
		return retval;
	}

}
