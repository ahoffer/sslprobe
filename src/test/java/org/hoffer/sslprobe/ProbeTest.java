package org.hoffer.sslprobe;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ProbeTest {

  static int port;
  static String localhostSelfSignedWithKeyPair;

  @BeforeAll
  static void beforeAll() {
    port = 8443;
    localhostSelfSignedWithKeyPair = ProbeTest.class.getResource("/localhost.p12").getPath();
  }

  @Test
  void positiveTest() throws Exception {
    String keystorePath = ProbeTest.class.getResource("/localhost.p12").getPath();
    SSLServerSocket sslServerSocket =
        (SSLServerSocket)
            ContextFactory.server(keystorePath, "changeit")
                .getContext()
                .getServerSocketFactory()
                .createServerSocket(port);
    Server server = new Server(sslServerSocket, "OK");
    server.start();
        Probe probe =
            new Probe(
                "localhost", String.valueOf(port), localhostSelfSignedWithKeyPair, "",
     "changeit");
       assertThat( probe.probe()).isInstanceOf(SSLSession.class);
  }
}
