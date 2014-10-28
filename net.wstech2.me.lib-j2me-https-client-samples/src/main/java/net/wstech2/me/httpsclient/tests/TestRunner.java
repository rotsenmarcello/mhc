/* Copyright 2014 WS/Tech² Informatica LTDA.
 * 
 * MHC (ME HTTPS Client) - An alternative J2ME Https Client.
 * 
 * http://www.wstech2.net/mhc/
 * 
 * Sample Code.
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

import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;

import net.wstech2.me.httpsclient.HttpsConnectionUtils;

public class TestRunner extends MIDlet {

	// enter http web server hostname or ip
	//final public static String HTTP_TEST_HOSTNAME = "j2metest.local";
	final public static String TEST_DEST_HOSTNAME = "www.google.ca";

	// enter http web server tcp port
	final public static String TEST_DEST_HTTP_PORT = "80";
	
	// enter https web server tcp port
		final public static String TEST_DEST_HTTPS_PORT = "443";

	public static final String TEST_HTTP_PROTOCOL_REQUEST_PATH = "/";

	public static final String TEST_HTTP_PROTOCOL_REQUEST = 
			"GET "
			+ TEST_HTTP_PROTOCOL_REQUEST_PATH
			+ " HTTP/1.0\r\nHost: "
			+ TEST_DEST_HOSTNAME
			+ ":"
			+ TEST_DEST_HTTPS_PORT + "\r\n\r\n";

	protected void destroyApp(boolean arg0) throws MIDletStateChangeException {

	}

	protected void pauseApp() {

	}

	protected void startApp() throws MIDletStateChangeException {
		
		
		ConnectionTest[] tests = {
				new HttpConnectionWithoutCryptography(),
				new HttpsConnectionWithDeviceDefaultImplementationTest(),
				new HttpsConnectionWithDirectSocketAndBCTlsHandlerTest(),
				new HttpsConnectionWithLibMeHttpsClientTest(),
		};
		
		for(int i=0;i<tests.length; i++){
			HttpsConnectionUtils
			.logDebug("\n\n\n++------- "
					+ tests[i].getClass().getName()
					+ "------++");
			try{
				((ConnectionTest)tests[i]).run();	
			}
			catch(Throwable t){
				HttpsConnectionUtils.logError("[ERROR] "
						+ tests[i].getClass().getName()
						+ " throwed the following Exception.",t);
			}
			
		}
	}

}
