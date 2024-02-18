package org.hoffer.sslprobe;

import static org.assertj.core.api.Assertions.assertThat;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ClientTest {

  static int port;
  static String localhostSelfSignedWithKeyPair;

  @BeforeAll
  static void beforeAll() {
    port = 8443;
    localhostSelfSignedWithKeyPair = ClientTest.class.getResource("/localhost.p12").getPath();
  }

  @Test
  void positiveTest() throws Exception {
    String keystorePath = ClientTest.class.getResource("/localhost.p12").getPath();
    SSLServerSocket serverSocket =
        (SSLServerSocket)
            ContextFactory.server(keystorePath, "changeit")
                .getContext()
                .getServerSocketFactory()
                .createServerSocket(port);
    Server server = new Server(serverSocket, "Nice to meet you");
    server.start();
    Client client =
        new Client(
            "localhost", String.valueOf(port), localhostSelfSignedWithKeyPair, "", "changeit");
    SSLSession session = client.connect();
    assertThat(session).isInstanceOf(SSLSession.class);

    String output = new SessionFormatter(session).format();
  }
}
