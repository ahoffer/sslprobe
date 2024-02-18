package org.hoffer.sslprobe;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.time.Duration;

/** Find out if a host is reachable and if it is listening on a particular port */
public class RemoteHostProbe {

  private final Duration timeout;

  public RemoteHostProbe(Duration timeout) {
    this.timeout = timeout;
  }

  public enum HostStatus {
    REACHABLE,
    UNREACHABLE,
    UNKNOWNHOST,
    NOLISTENER
  }

  public HostStatus isReachable(String host) {
    try {
      InetAddress inetAddress = InetAddress.getByName(host);
      return inetAddress.isReachable((int) timeout.toMillis())
          ? HostStatus.REACHABLE
          : HostStatus.UNREACHABLE;
    } catch (UnknownHostException e) {
      return HostStatus.UNKNOWNHOST;
    } catch (IOException e) {
      return HostStatus.UNREACHABLE;
    }
  }

  public boolean isListeningOnPort(String host, int port) {
    try (Socket ignored = new Socket(host, port)) {
      return true; // Successfully connected to the port
    } catch (IOException e) {
      return false; // Couldn't connect to the port
    }
  }

  public HostStatus probe(String host, int port) {
    HostStatus status = isReachable(host); // Utilizing isReachable directly

    if (status == HostStatus.REACHABLE && port > 0 && !isListeningOnPort(host, port)) {
      return HostStatus.NOLISTENER;
    }

    return status;
  }
}
