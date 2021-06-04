
package com.simdevmon.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Shared TLS resouces.
 *
 * @author simdemon
 */
public class TlsCommon
{

    public static final int PORT = 32333;

    public static final String TLS_PROTOCOL = "TLSv1.3";

    public static final String[] CIPHER_SUITES = new String[]
    {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384"
    };

    public static KeyStore createKeystore(String password)
    {
        try
        {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, password.toCharArray());
            return ks;
        }
        catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex)
        {
            throw new IllegalStateException(ex);
        }
    }

    public static Certificate convertCertificate(String cert) throws CertificateException
    {
        InputStream in = new ByteArrayInputStream(cert.getBytes(StandardCharsets.ISO_8859_1));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return certFactory.generateCertificate(in);
    }

    public static PrivateKey convertPrivateKey(String key)
    {
        try
        {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(key
                    .replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "")
                    .replaceAll("\r", "")
                    .replaceAll("\n", ""))));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException ex)
        {
            throw new IllegalStateException(ex);
        }
    }
}
