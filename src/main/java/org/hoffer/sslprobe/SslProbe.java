package org.hoffer.sslprobe;

import static org.hoffer.sslprobe.RemoteHostProbe.HostStatus.REACHABLE;
import static org.springframework.shell.command.CommandRegistration.OptionArity.EXACTLY_ONE;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.jline.terminal.Terminal;
import org.springframework.shell.command.annotation.Command;
import org.springframework.shell.command.annotation.Option;

@Command
public class SslProbe {

  final Terminal terminal;

  RemoteHostProbe hostProbe = new RemoteHostProbe(Duration.ofSeconds(3));

  public SslProbe(Terminal terminal) {
    this.terminal = terminal;
  }

  @Command
  public String probe(
      @Option(
              description = "path to the keystore",
              shortNames = {'k'},
              arity = EXACTLY_ONE)
          String keystore,
      @Option(
              description = "path to the truststore",
              shortNames = {'t'},
              arity = EXACTLY_ONE)
          String truststore,
      @Option(
              description = "common password",
              shortNames = {'w'},
              arity = EXACTLY_ONE)
          String password,
      @Option(
              description = "remote host",
              // short name 'h' is already taken by "help"
              shortNames = {'u'},
              arity = EXACTLY_ONE)
          String host,
      @Option(
              description = "port",
              shortNames = {'p'},
              arity = EXACTLY_ONE)
          String port)
      throws CertificateException,
          IOException,
          KeyStoreException,
          NoSuchAlgorithmException,
          UnrecoverableKeyException,
          KeyManagementException {
    try {
      int iport = parsePort(port);

      RemoteHostProbe.HostStatus reachable = hostProbe.isReachable(host);
      if (reachable != REACHABLE) {
        return reachable.toString();
      }

      if (!hostProbe.isListeningOnPort(host, iport)) {
        return String.format("\"%s\" is not listening on port %d", host, iport);
      }

      KeyStore keyStore = loadFile(keystore, password);
      KeyStore trustStore = loadFile(truststore, password);
      SSLContext sslContext = createSslContext(password, keyStore, trustStore);
      shakeHands(sslContext, host, iport);
    } catch (SslProbeException e) {
      return e.getMessage();
    }
    return "";
  }

  void shakeHands(SSLContext sslSocketFactory, String host, int port) throws IOException {
    SSLSocket sslSocket = (SSLSocket) sslSocketFactory.getSocketFactory().createSocket(host, port);
    try {
      sslSocket.startHandshake();
      terminal.writer().println("SSL handshake successful");
      //TODO print out parameters
      SSLSession s = sslSocket.getSession();
      SSLParameters p = sslSocket.getSSLParameters();
    } finally {
      sslSocket.close();
    }
  }

  SSLContext createSslContext(String password, KeyStore keyStore, KeyStore trustStore)
      throws NoSuchAlgorithmException,
          KeyManagementException,
          UnrecoverableKeyException,
          KeyStoreException {
    String sslContextAlgorithm = "TLS";
    SSLContext sslContext = SSLContext.getInstance(sslContextAlgorithm);
    sslContext.init(keyManagers(keyStore, password), trustManagers(trustStore), null);
    return sslContext;
  }

  int parsePort(String port) {
    int iport;
    try {
      iport = Integer.parseInt(port);
    } catch (NumberFormatException e) {
      throw new SslProbeException(
          String.format("Port must be an integer but \"%s\" could not be converted", port));
    }
    return iport;
  }

  KeyStore loadFile(String path, String password)
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

  KeyManager[] keyManagers(KeyStore keyStore, String password)
      throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, password.toCharArray());
    return keyManagerFactory.getKeyManagers();
  }

  TrustManager[] trustManagers(KeyStore trustStore)
      throws NoSuchAlgorithmException, KeyStoreException {
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    return trustManagerFactory.getTrustManagers();
  }
}

final class SslProbeException extends RuntimeException {
  SslProbeException(String msg) {
    super(msg);
  }

  SslProbeException(String msg, Throwable throwable) {
    super(msg, throwable);
  }
}
