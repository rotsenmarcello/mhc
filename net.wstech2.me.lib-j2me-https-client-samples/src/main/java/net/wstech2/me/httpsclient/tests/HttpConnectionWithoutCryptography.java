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

import net.wstech2.me.httpsclient.HttpsConnectionUtils;

import java.io.*;

public class HttpConnectionWithoutCryptography implements ConnectionTest {


	public boolean run() {
		String response = null;
		HttpConnection connection = null;
		boolean httpRequestOK = false;
		String url = "http://" 
				+ TestRunner.TEST_DEST_HOSTNAME 
				+ ":"
				+ TestRunner.TEST_DEST_HTTP_PORT 
				+ TestRunner.TEST_HTTP_PROTOCOL_REQUEST_PATH;
		HttpsConnectionUtils.logDebug("[HTTP Test without Cryptgraphy] -> STARTING");
		HttpsConnectionUtils.logDebug("[HTTP Test without Cryptgraphy] -> URL [" + url + "]");
		try {

			connection = (HttpConnection) Connector.open(url);

			response = TestUtils.getResponse("[HTTP Test without Cryptgraphy]", connection.openInputStream());
			HttpsConnectionUtils.logDebug("[HTTP Test without Cryptgraphy] -> Request returned the following CONTENT:\n");
			HttpsConnectionUtils.logDebug(response);
			httpRequestOK = true;
			
		} catch (Exception e) {
			HttpsConnectionUtils.logError("[HTTP Test without Cryptgraphy] -> Request test ended abnormally with the following error: ",
					e);

		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (IOException e) {
				}
			}
		}
		HttpsConnectionUtils.logDebug("[HTTP Test without Cryptgraphy] -> Test result: [" + (httpRequestOK ? "Success" : "Error") + "].");
		HttpsConnectionUtils.logDebug("[HTTP Test without Cryptgraphy] -> FINISHED");
		return httpRequestOK;
	}
}
