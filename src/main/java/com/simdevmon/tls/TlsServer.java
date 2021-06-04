
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
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Sample TLS server.
 *
 * @author simdevmon
 */
public class TlsServer
{

    public static final String SERVER_CRT = "-----BEGIN CERTIFICATE-----\n"
        // ...
        + "-----END CERTIFICATE-----";

    private static final String SERVER_KEY
        = "-----BEGIN PRIVATE KEY-----\n"
        // ...
        + "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws Exception
    {
        new TlsServer().start();
    }

    private void start() throws Exception
    {
        //System.setProperty("javax.net.debug", "all");
        String ksPass = "changeit";

        // Init Key Manager Factory.
        KeyStore kks = TlsCommon.createKeystore(ksPass);
        kks.setKeyEntry("server", TlsCommon.convertPrivateKey(SERVER_KEY), ksPass.toCharArray(), new Certificate[]
        {
            TlsCommon.convertCertificate(SERVER_CRT)
        });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(kks, ksPass.toCharArray());

        // Init Trust Manager Factory.
        KeyStore tks = TlsCommon.createKeystore(ksPass);
        tks.setCertificateEntry("client", TlsCommon.convertCertificate(TlsClient.CLIENT_CRT));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(tks);

        // Init SSL Context.
        SSLContext ctx = SSLContext.getInstance(TlsCommon.TLS_PROTOCOL);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Init Server Socket.
        SSLServerSocket serverSocket = (SSLServerSocket) ctx.getServerSocketFactory()
            .createServerSocket(TlsCommon.PORT);
        serverSocket.setNeedClientAuth(true);
        serverSocket.setEnabledCipherSuites(TlsCommon.CIPHER_SUITES);
        serverSocket.setEnabledProtocols(new String[]
        {
            TlsCommon.TLS_PROTOCOL
        });

        System.out.printf("Server started on port %d%n", TlsCommon.PORT);
        while (true)
        {
            try ( SSLSocket socket = (SSLSocket) serverSocket.accept())
            {
                System.out.println("Accept connection: " + socket.getRemoteSocketAddress());
                InputStream is = new BufferedInputStream(socket.getInputStream());
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0)
                {
                    throw new IOException("No data received.");
                }
                System.out.printf("Server received %d bytes: %s%n", len, new String(data, 0, len));
                os.write(data, 0, len);
                os.flush();
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }
        }
    }
}
