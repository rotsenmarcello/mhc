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
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.microedition.rms.InvalidRecordIDException;
import javax.microedition.rms.RecordStore;
import javax.microedition.rms.RecordStoreException;
import javax.microedition.rms.RecordStoreFullException;
import javax.microedition.rms.RecordStoreNotFoundException;
import javax.microedition.rms.RecordStoreNotOpenException;

import org.bouncycastle.asn1.x509.Certificate;

/**
 * 
 * CertificateStore interacts with the Certificate Authorities repository,
 * providing methods for insertion, removal, deletion and maintenance of the
 * stored certificates.
 * 
 * This repository contains CA's (Certificate Authorities) public keys and
 * server certificates stored in both the app jar resources and the record store.
 * 
 * Certificates shipped with the application are stored as resources, and those
 * added during the application lifetime are stored as records in the Record
 * Store.
 * 
 */
public class CertificateStore {

	private Hashtable certificateIdsMap = new Hashtable();
	private RecordStore recordStore;
	private static CertificateStore instance = new CertificateStore();

	public static CertificateStore getInstance() {
		return instance;
	}

	/**
	 * Insert a new certificate into the Certificate Store. This new certificate
	 * will be saved, internally, as a record in the Record Store.
	 * 
	 * @param cn
	 *            common name
	 * @param certificate
	 *            The certificate to be saved (stored). This certificate will be
	 *            serialized as an array of bytes and then stored as an record.
	 * @throws IOException
	 * @throws RecordStoreException
	 * @throws RecordStoreFullException
	 * @throws RecordStoreNotOpenException
	 * 
	 */
	public void put(String cn,
			org.bouncycastle.asn1.x509.Certificate certificate)
			throws IOException, RecordStoreNotOpenException,
			RecordStoreFullException, RecordStoreException {
		byte[] encoded = certificate.getEncoded();
		int recordId = -1;
		if (certificateIdsMap.get(cn) != null) {
			recordId = Integer.valueOf((String) certificateIdsMap.get(cn))
					.intValue();
			recordStore.setRecord(recordId, encoded, 0, encoded.length);
		} else {
			recordId = recordStore.addRecord(encoded, 0, encoded.length);
		}
		certificateIdsMap.put(cn, String.valueOf(recordId));
		saveCertificateIdsMap();
	}

	/**
	 * Gets a certificate from the Certificate Store corresponding to the
	 * subject passed as parameter.
	 * 
	 * @param cn
	 *            common name
	 * 
	 * @return The certificate corresponding to the common name informed. Null
	 *         if no certificate could be found.
	 * @throws RecordStoreException
	 * @throws InvalidRecordIDException
	 * @throws RecordStoreNotOpenException
	 */
	public Certificate get(String cn) throws RecordStoreNotOpenException,
			InvalidRecordIDException, RecordStoreException {
		if (certificateIdsMap.get(cn) == null) {
			return null;
		}
		int recordId = Integer.valueOf((String) certificateIdsMap.get(cn))
				.intValue();
		return Certificate.getInstance(recordStore.getRecord(recordId));
	}

	/**
	 * Remove the certificate from the Certificate Store. It will only remove
	 * certificates from the Record Store. The certificates shipped as
	 * resources in the application jar can not be removed.
	 * 
	 * @param cn
	 *            common name.
	 * 
	 * @throws RecordStoreException
	 * @throws InvalidRecordIDException
	 * @throws RecordStoreNotOpenException
	 */
	public void remove(String cn) throws RecordStoreNotOpenException,
			InvalidRecordIDException, RecordStoreException {
		int recordId = Integer.valueOf((String) certificateIdsMap.get(cn))
				.intValue();
		certificateIdsMap.remove(cn);
		recordStore.deleteRecord(recordId);
		saveCertificateIdsMap();
	}

	/**
	 * 
	 * Loads or initializes the RecordStore containing the stored certificates.
	 * 
	 * @return an instance of the RecordStore.
	 * @throws RecordStoreException
	 * @throws RecordStoreNotFoundException
	 * @throws RecordStoreFullException
	 * 
	 */
	public RecordStore initRecordStore() throws RecordStoreFullException,
			RecordStoreNotFoundException, RecordStoreException {
		if (recordStore == null) {
			recordStore = RecordStore.openRecordStore("certificateStore", true);
			loadCertificateIdsMap();
		}
		return recordStore;
	}

	/**
	 * Stores the certficate ids map into the record store.
	 * 
	 * @throws RecordStoreException
	 * @throws RecordStoreFullException
	 * @throws InvalidRecordIDException
	 * @throws RecordStoreNotOpenException
	 */
	public void saveCertificateIdsMap() throws RecordStoreNotOpenException,
			InvalidRecordIDException, RecordStoreFullException,
			RecordStoreException {

		String certificateIdsMapStr = "";
		Enumeration keys = certificateIdsMap.elements();
		while (keys.hasMoreElements()) {
			Object cn = keys.nextElement();
			Object recordId = keys.nextElement();
			certificateIdsMapStr = certificateIdsMapStr + recordId + ":" + cn
					+ "\n";
		}
		if (recordStore.getNumRecords() == 0) {
			recordStore.addRecord(certificateIdsMapStr.getBytes(), 0,
					certificateIdsMapStr.getBytes().length);
		}
		recordStore.setRecord(1, certificateIdsMapStr.getBytes(), 0,
				certificateIdsMapStr.getBytes().length);
	}

	/**
	 * 
	 * Loads the certificate identifiers from the recordStore's Record ID 1.
	 * Those identifiers will be used to locate and, if needed, load
	 * certificates saved in the recordStore.
	 * 
	 * 
	 */
	public void loadCertificateIdsMap() {
		try {
			if (recordStore.getNumRecords() > 0) {
				String maps = new String(recordStore.getRecord(1));
				StringTokenizer certificateIdsMapStr = new StringTokenizer(
						maps, "\n");
				certificateIdsMap.clear();
				while (certificateIdsMapStr.hasMoreTokens()) {
					String record = certificateIdsMapStr.nextToken();
					int sep = record.indexOf(":");
					String recordId = record.substring(0, sep);
					String cn = record.substring(sep + 1);
					certificateIdsMap.put(cn, recordId);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
