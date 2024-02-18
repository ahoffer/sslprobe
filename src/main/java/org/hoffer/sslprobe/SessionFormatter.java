package org.hoffer.sslprobe;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

public class SessionFormatter {

  final SSLSession session;

  public SessionFormatter(SSLSession session) {
    this.session = session;
  }

  public String format() {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    PrintStream printer = new PrintStream(content);
    printer.printf("Protocol = %s", session.getProtocol());
    printer.printf("Remote principal = %s", peerPrincipal());
    printer.printf("Remote host = %s:%d", session.getPeerHost(), session.getPeerPort());
    printer.printf("Cipher suite = %s", session.getCipherSuite());

    //    printer.println("Remote certs =");
    //    printPeerCerts(printer);

    printer.println("Local certs =");
    printLocalCerts(printer);
    printer.flush();
    return content.toString();
  }

  void printPeerCerts(PrintStream printer) {
    try {
      Certificate[] peerCerts = session.getPeerCertificates();
      Arrays.stream(peerCerts).forEach(cert -> printer.printf("\t%s", cert.toString()));
    } catch (SSLPeerUnverifiedException e) {
      printer.printf("\t%s", e.getMessage());
    }
  }

  void printLocalCerts(PrintStream printer) {
    Certificate[] certs = session.getLocalCertificates();
    if (certs == null) {
      printer.println("\tNo ctertificates sent to peer during handshaking");
    } else {
      Arrays.stream(certs).forEach(cert -> printer.printf("\t%s", cert.toString()));
    }
  }

  String peerPrincipal() {
    try {
      return session.getPeerPrincipal().getName();
    } catch (SSLPeerUnverifiedException e) {
      return e.getMessage();
    }
  }
}
