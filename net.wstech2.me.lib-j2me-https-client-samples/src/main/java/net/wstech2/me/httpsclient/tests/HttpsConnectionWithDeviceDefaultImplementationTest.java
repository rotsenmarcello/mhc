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

public class HttpsConnectionWithDeviceDefaultImplementationTest implements ConnectionTest {

	public void run() {
		String response = null;
		HttpConnection connection = null;
		boolean httpsRequestOK = false;
		String url = "https://" 
				+ TestRunner.TEST_DEST_HOSTNAME 
				+ ":"
				+ TestRunner.TEST_DEST_HTTPS_PORT 
				+ TestRunner.TEST_HTTP_PROTOCOL_REQUEST_PATH;
		HttpsConnectionUtils.logDebug("[HTTPS Test with Device Implementation] -> STARTING");
		HttpsConnectionUtils.logDebug("[HTTPS Test with Device Implementation] -> URL [" + url + "]");
		try {

			connection = (HttpConnection) Connector.open(url);

			response = TestUtils.getResponse("[HTTPS Test with Device Implementation]", connection.openInputStream());
			HttpsConnectionUtils.logDebug("[HTTPS Test with Device Implementation] -> Request returned the following CONTENT:\n");
			HttpsConnectionUtils.logDebug(response);
			httpsRequestOK = true;
			
		} catch (Exception e) {
			HttpsConnectionUtils.logError("[HTTPS Test with Device Implementation] -> Request test ended abnormally with the following error: ",
					e);

		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (IOException e) {
				}
			}
		}
		HttpsConnectionUtils.logDebug("[HTTPS Test with Device Implementation] -> Test result: [" + (httpsRequestOK ? "Success" : "Error") + "].");
		HttpsConnectionUtils.logDebug("[HTTPS Test with Device Implementation] -> FINISHED");
		
	}
}
