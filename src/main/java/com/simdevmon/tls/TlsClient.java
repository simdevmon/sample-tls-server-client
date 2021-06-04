
package com.simdevmon.tls;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Sample TLS client.
 *
 * @author simdevmon
 */
public class TlsClient
{

    public static final String CLIENT_CRT = "-----BEGIN CERTIFICATE-----\n"
        // ...
        + "-----END CERTIFICATE-----";

    private static final String CLIENT_KEY
        = "-----BEGIN PRIVATE KEY-----\n"
        // ...
        + "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws Exception
    {
        new TlsClient().start();
    }

    private void start() throws Exception
    {
        //System.setProperty("javax.net.debug", "all");
        String ksPw = "changeit";

        // Init Key Manager Factory.
        KeyStore ks = TlsCommon.createKeystore(ksPw);
        ks.setKeyEntry("client", TlsCommon.convertPrivateKey(CLIENT_KEY), ksPw.toCharArray(), new Certificate[]
        {
            TlsCommon.convertCertificate(CLIENT_CRT)
        });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, ksPw.toCharArray());

        // Init Trust Manager Factory.
        KeyStore ts = TlsCommon.createKeystore(ksPw);
        ts.setCertificateEntry("server", TlsCommon.convertCertificate(TlsServer.SERVER_CRT));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        // Init SSL context.
        SSLContext ctx = SSLContext.getInstance(TlsCommon.TLS_PROTOCOL);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Socket connection.
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", TlsCommon.PORT);
        socket.setEnabledCipherSuites(TlsCommon.CIPHER_SUITES);
        socket.setEnabledProtocols(new String[]
        {
            TlsCommon.TLS_PROTOCOL
        });

        System.out.println("Connected: " + socket.isConnected());
        Thread.sleep(1000);
        InputStream is = new BufferedInputStream(socket.getInputStream());
        OutputStream os = new BufferedOutputStream(socket.getOutputStream());
        os.write("Hello World".getBytes());
        os.flush();
        byte[] data = new byte[2048];
        int len = is.read(data);
        if (len <= 0)
        {
            throw new IOException("No data received.");
        }
        System.out.printf("Client received %d bytes: %s%n", len, new String(data, 0, len));
    }
}
