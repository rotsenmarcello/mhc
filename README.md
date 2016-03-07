
About MHC (ME-Https-Client)
===========================

MHC (ME-Https-Client) is a J2ME library written in Java which offers an alternative implementation 
for the javax.microedition.io.HttpsConnection interface.

You can use it to connect to secure (SSL/TLS) websites, specially when the default implementation 
of a particular device does not support SSL/TLS certificates issued by non-trusted certificate 
authorities nor does it allow the possibility to install these certs/keys into its certificate store.

It is released under the Apache License 2.0.

Web site: http://www.wstech2.net/mhc/

GitHub repository: https://github.com/rotsenmarcello/mhc/.



Quick Usage Guide
=================

Set up an Eclipse workspace for Java;

Download the file lcrypto-j2me-151.zip from the bouncy castle website, extract it to an 
eclipse project and configure it to a maven project with the name org.bouncycastle.lcrypto-j2me 
using the pom.xml available at the download page;

Delete the folder /src/main/java/org/bouncycastle/openpgp/examples/ 
in the project org.bouncycastle.lcrypto-j2me;

Apply the patch lcrypto-j2me-151.patch on the project described above. This patch corrects 
some minor defects regarding EOF issues;

Build and install the artifact org.bouncycastle.lcrypto-j2me-1.51.jar by issuing a 
"maven clean install" command at the project directory;

Download the MHC (ME-Https-Client) library sources net.wstech2.me.lib-j2me-https-client, extract 
them to a Eclipse project and build the maven artifact by issuing the command "maven clean install" 
at the project's root directory;

Download the MHC (ME-Https-Client) library Code Samples net.wstech2.me.lib-j2me-https-client-samples, 
extract them to a Eclipse project and build the maven artifact by issuing the command 
"maven -Pdebug clean install" at the project's root directory.
The sample project's POM can be used as a reference when configuring other projects using MHC. 
By doing that, special attention must be paid to POM parameters related to obfuscation, preverification 
and jad attributes configuration, like: proguardOptions, proguardPreverify, midlets, jadAttributes, etc;

Create and open the connection by using the following code block:

```Java
HttpsConnection connection = new HttpsConnectionImpl(
					HTTPS_HOSTNAME, 
					HTTPS_PORT,
					HTTPS_CONNECTION_IMPL_PATH);
System.out.println("Response Message:  "
			+ connection.getResponseMessage());
String response = getResponse(connection.openInputStream()); 
System.out.println("HTTPS (HttpsConnectionImpl) "
	+ "request returned the following CONTENT:" + response);

private String getResponse(InputStream in) throws IOException {

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
```


<b>Where:</b>


HTTPS_HOSTNAME: is the hostname of the https site. For example: www.google.de
HTTPS_PORT: is the tcp port of the https site. For example: 443
HTTPS_CONNECTION_IMPL_PATH: is the path of the https site. For example: / or /dir/file.php

Finally, in order to validate a website certificate it is required to create a DER-formatted file in 
the MidLet's JAR containing the C.A.'s certificate used to sign the website or the certificate 
itself if it is a self-signed one.
IMPORTANT: The file name must follow exactly the content set for the "issuer" attribute from the 
issued certificate or the "CN" segment, if available, from the same attribute. For example, at the 
client-samples we are testing our client against the website https://www.google.ca:443/. 
In this case, the root CA "C=US,O=Equifax,OU=Equifax Secure Certificate Authority" is at the 
highest level of the signing hierarchy used by google, as indicated by the "issuer" attribute of its 
immediate child. Therefore, we have to place its certificate in a file called 
"C=US,O=Equifax,OU=Equifax Secure Certificate Authority.der" in the folder "/res/certs" of the Midlet JAR.

A sample certificate/key pair, with the respective C.A. certificate, is packaged along with 
the sample codes.
For this certificate the issuer subject is identified as 
"C=BR, ST=Parana, O=j2metest company, OU=j2metest unit name, CN=j2metest.local-ca". 
Hence, its certificate can stored in a file named either 
"C=BR, ST=Parana, O=j2metest company, OU=j2metest unit name, CN=j2metest.local-ca.der" 
or "j2metest.local-ca.der".

<b>IMPORTANT: These files are for test purposes only, they should not be applied in production 
environments.</b>


For more comprehensive details about the library usage and capabilities, please check the project 
net.wstech2.me.lib-j2me-https-client-samples.
