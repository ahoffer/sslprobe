package org.hoffer.sslprobe;

import static org.hoffer.sslprobe.RemoteHostProbe.HostStatus.REACHABLE;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.springframework.shell.command.annotation.Command;

@Command
public class Client {

  final String host;
  final int port;
  final String truststore;
  final String keystore;
  final String password;
  RemoteHostProbe hostProbe = new RemoteHostProbe(Duration.ofSeconds(3));

  public Client(String host, String port, String truststore, String keystore, String password) {
    this.host = host;
    this.port = parsePort(port);
    this.truststore = truststore;
    this.keystore = keystore;
    this.password = password;
  }

  public SSLSession connect() {
    try {
      RemoteHostProbe.HostStatus reachable = hostProbe.probe(host, port);
      if (reachable != REACHABLE) {
        throw new SslProbeException(
            String.format("\"%s\" is not listening on port %d", host, port));
      }
      SSLContext clientContext = ContextFactory.client(truststore, password).getContext();
      return shakeHands(clientContext);
    } catch (SslProbeException
        | IOException
        | KeyStoreException
        | CertificateException
        | NoSuchAlgorithmException
        | KeyManagementException
        | UnrecoverableKeyException e) {
      throw new SslProbeException(e.getMessage());
    }
  }

  SSLSession shakeHands(SSLContext sslContext) throws IOException {
    SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
    SSLSession session;
    try {
      socket.startHandshake();
      session = socket.getSession();
    } finally {
      socket.close();
    }
    return session;
  }

  int parsePort(String str) {
    int iport;
    try {
      iport = Integer.parseInt(str);
    } catch (NumberFormatException e) {
      throw new SslProbeException(
          String.format("Port must be an integer but \"%s\" could not be converted", port));
    }
    return iport;
  }
}
