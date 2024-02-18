package org.hoffer.sslprobe;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Common code for creating an SSL context from keystore paths and passwords. Use public static
 * methods to create an instance.
 */
public class ContextFactory {

  String keystorePath;
  String truststorePath;
  String password;

  public static ContextFactory twoWayTls(String keystore, String truststore, String password) {
    ContextFactory ssf = new ContextFactory();
    ssf.keystorePath = keystore;
    ssf.truststorePath = truststore;
    ssf.password = password;
    return ssf;
  }

  public static ContextFactory server(String keystore, String password) {
    ContextFactory ssf = new ContextFactory();
    ssf.keystorePath = keystore;
    ssf.truststorePath = "";
    ssf.password = password;
    return ssf;
  }

  public static ContextFactory client(String truststore, String password) {
    ContextFactory ssf = new ContextFactory();
    ssf.keystorePath = "";
    ssf.truststorePath = truststore;
    ssf.password = password;
    return ssf;
  }

  public SSLContext getContext()
      throws CertificateException,
          IOException,
          KeyStoreException,
          NoSuchAlgorithmException,
          UnrecoverableKeyException,
          KeyManagementException {
    // Keystore needed for server and 2-way TLS
    KeyStore keyStore = null;
    if (!keystorePath.isBlank()) {
      keyStore = loadFile(keystorePath);
    }
    // Truststore needed for client and 2-way TLS
    KeyStore trustStore = null;
    if (!truststorePath.isBlank()) {
      trustStore = loadFile(truststorePath);
    }

    return createSslContext(keyStore, trustStore);
  }

  SSLContext createSslContext(KeyStore keyStore, KeyStore trustStore)
      throws NoSuchAlgorithmException,
          KeyManagementException,
          UnrecoverableKeyException,
          KeyStoreException {
    String sslContextAlgorithm = "TLS";
    SSLContext sslContext = SSLContext.getInstance(sslContextAlgorithm);

    // TODO: Let users specify this value. Often it is the same as the keystore password
    String keyPassword = "";

    sslContext.init(keyManagers(keyStore, keyPassword), trustManagers(trustStore), null);
    return sslContext;
  }

  KeyManager[] keyManagers(KeyStore keyStore, String keyPassword)
      throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

    keyManagerFactory.init(keyStore, keyPassword.toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  TrustManager[] trustManagers(KeyStore trustStore)
      throws NoSuchAlgorithmException, KeyStoreException {
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    return trustManagerFactory.getTrustManagers();
  }

  KeyStore loadFile(String path)
      throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    String defaultType = KeyStore.getDefaultType();
    try (FileInputStream fis = new FileInputStream(path)) {
      KeyStore keystore = KeyStore.getInstance(defaultType);
      try {
        keystore.load(fis, password.toCharArray());
      } catch (IOException e) {
        // Handle bad password
        if (e.getCause() instanceof java.security.UnrecoverableKeyException) {
          throw new SslProbeException(String.format("Password was not correct for \"%s\"", path));
        }
        // Rethrow any other cause
        throw e;
      }
      return keystore;
    }
  }
}
