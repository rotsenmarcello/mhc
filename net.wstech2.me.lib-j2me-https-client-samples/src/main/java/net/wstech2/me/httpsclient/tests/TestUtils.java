/* Copyright 2011 WS/Tech² Informatica LTDA.
 * 
 * MHC (ME HTTPS Client) - An alternative J2ME Https Client.
 * 
 * http://www.wstech2.net/mhc/
 * 
 * Sample Code.
 *
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

package net.wstech2.me.httpsclient.tests;

import net.wstech2.me.httpsclient.HttpsConnectionUtils;

import org.bouncycastle.crypto.tls.*;

import java.io.*;

public class TestUtils {

	
	
	public static String getSSLResponse(InputStream in, OutputStream out,
			String request) throws IOException {
		String retval = null;
		TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(in, out);
		DefaultTlsClient tlsClient = new DefaultTlsClient() {

			public TlsAuthentication getAuthentication() throws IOException {
				return new TlsAuthentication() {

					public void notifyServerCertificate(
							Certificate serverCertificate) throws IOException {
					}

					public TlsCredentials getClientCredentials(
							CertificateRequest certificateRequest)
							throws IOException {
						return null;
					}
				};
			}
		};

		tlsClientProtocol.connect(tlsClient);
		retval = getResponse(tlsClientProtocol.getInputStream(),
				tlsClientProtocol.getOutputStream(), request);
		tlsClientProtocol.close();
		return retval;
	}

	public static String getResponse(String callerLogPrefix, InputStream in) throws IOException {

		StringBuffer retval = new StringBuffer();
		byte[] content = new byte[5];

		int read = 0;
		while ((read = in.read(content)) != -1) {
			// this is for testing purposes only
			// an adequate solution should handle charsets here
			retval.append(new String(content, 0, read));

		}

		return retval.toString();
	}

	public static String getResponse(InputStream in, OutputStream out, String request)
			throws IOException {

		StringBuffer retval = new StringBuffer();
		byte[] content = new byte[100];
		out.write(request.getBytes());
		out.flush();

		int read = 0;
		while ((read = in.read(content)) != -1) {
			HttpsConnectionUtils.logDebug("Reading " + read + " bytes[ " + new String(content, 0, read)
					+ "]");
			retval.append(new String(content, 0, read));
		}

		return retval.toString();
	}
}
