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

import javax.microedition.io.*;

import java.io.*;

import net.wstech2.me.httpsclient.HttpsConnectionUtils;

public class HttpsConnectionWithDirectSocketAndBCTlsHandlerTest implements ConnectionTest{

	

	public boolean run() throws Exception {
		String response = null;
		SocketConnection connection = null;
		boolean httpsRequestOK = false;
		String url = "socket://" + TestRunner.TEST_DEST_HOSTNAME + ":" + TestRunner.TEST_DEST_HTTPS_PORT;
		TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> STARTING");
		TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> URL [" + url + "]");
		try {

			connection = (SocketConnection) Connector.open(url, Connector.READ_WRITE);
			TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> Connection Opened");
			InputStream in = connection.openInputStream();
			OutputStream out = connection.openOutputStream();

			TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> Calling getResponse");
			response = TestUtils.getSSLResponse(in, out, TestRunner.TEST_HTTP_PROTOCOL_REQUEST);
			TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> Request returned the following CONTENT:\n");
			TestRunner.getInstance().logDebug(response);
			httpsRequestOK = true;
			in.close();
			out.close();
			connection.close();
		} catch (Exception e) {
			
			HttpsConnectionUtils.logError("[HTTPS Test with Direct Socket / BC TLS Handler] -> HTTP over Socket /TLSHandler request test ended abnormally with the following error: ",
					e);
			throw e;

		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (IOException e) {
				}
			}
		}// end of HTTPS test

		// Summary
		TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> Test result:"
				+ (httpsRequestOK ? "Success" : "Error") + ".");
		TestRunner.getInstance().logDebug("[HTTPS Test with Direct Socket / BC TLS Handler] -> FINISHED");
		return httpsRequestOK;
	}
}
