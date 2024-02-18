package org.hoffer.sslprobe;

import org.springframework.boot.web.server.Ssl;

import javax.net.ssl.SSLSession;
import java.io.PrintWriter;

public class SessionFormatter {

    final SSLSession session;

    public SessionFormatter(SSLSession session) {
        this.session = session;
    }

    public void format(PrintWriter writer) {
        writer.println();
    }

}
