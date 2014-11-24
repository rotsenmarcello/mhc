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

import net.wstech2.me.httpsclient.HttpsConnectionImpl;
import net.wstech2.me.httpsclient.HttpsConnectionUtils;

public class HttpsConnectionWithLibMeHttpsClientTest implements ConnectionTest{

	

	public boolean run() throws Exception {
		String response = null;
		HttpsConnection connection = null;
		boolean httpsRequestOK = false;
		String url = "https://" + TestRunner.TEST_DEST_HOSTNAME + ":" + TestRunner.TEST_DEST_HTTPS_PORT
				+ TestRunner.TEST_HTTP_PROTOCOL_REQUEST_PATH;
		HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> STARTING");
		HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> URL [" + url + "]");
		try {

			connection = new HttpsConnectionImpl(TestRunner.TEST_DEST_HOSTNAME, 
					Integer.valueOf(TestRunner.TEST_DEST_HTTPS_PORT).intValue(),
					TestRunner.TEST_HTTP_PROTOCOL_REQUEST_PATH);

			HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> Response Message:  " + connection.getResponseMessage());
			response = TestUtils.getResponse("[HTTPS Test with lib MHC (Me HTTPS Client)]", connection.openInputStream());
			HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> Request returned the following CONTENT:\n");
			HttpsConnectionUtils.logDebug(response);
			httpsRequestOK = true;
		} catch (Exception e) {
			HttpsConnectionUtils.logError("[HTTPS Test with lib MHC (Me HTTPS Client)] -> Request test ended abnormally with the following error: ",
					e);
			throw e;
		} finally {
			if (connection != null) {
				try {
					connection.close();
				} catch (IOException e) {
				}
			}
		}
		// Summary
		HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> Test result: ["
				+ (httpsRequestOK ? "Success" : "Error") + "].");
		HttpsConnectionUtils.logDebug("[HTTPS Test with lib MHC (Me HTTPS Client)] -> FINISHED");
		return httpsRequestOK;
	}

}
