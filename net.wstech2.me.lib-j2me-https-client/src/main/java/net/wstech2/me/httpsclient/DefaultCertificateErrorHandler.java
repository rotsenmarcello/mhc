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

import javax.microedition.lcdui.Alert;
import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import org.bouncycastle.asn1.x509.Certificate;


public class DefaultCertificateErrorHandler implements CommandListener,
		CertificateErrorHandler {

	protected Alert alert;
	protected Display display;

	private final Command CANCEL_COMMAND = new Command("Cancel",
			Command.CANCEL, 0);

	private final Command CONTINUE_COMMAND = new Command("OK", Command.OK, 0);

	public DefaultCertificateErrorHandler(Display display) {
		this.display = display;
		alert = new Alert("Certificate Error");
		alert.setTimeout(Alert.FOREVER);
		alert.addCommand(CANCEL_COMMAND);
		alert.addCommand(CONTINUE_COMMAND);
		alert.setCommandListener(this);
	}

	public int onCertificateValidationError(Certificate cert, int[] errors,
			HttpsConnectionImpl httpsConnectionInstance,
			CertificateValidator certificateValidatorInstance) {

		return CertificateErrorHandler.ON_ERROR_CONTINUE;
	}

	public void commandAction(Command cmd, Displayable displayable) {
		if (cmd == CANCEL_COMMAND) {

		} else if (cmd == CONTINUE_COMMAND) {

		}
	}

}
