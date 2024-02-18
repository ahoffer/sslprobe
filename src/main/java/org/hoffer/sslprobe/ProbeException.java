package org.hoffer.sslprobe;

class SslProbeException extends RuntimeException {
  SslProbeException(String msg) {
    super(msg);
  }

  SslProbeException(String msg, Throwable throwable) {
    super(msg, throwable);
  }

  SslProbeException(Throwable throwable) {
    super(throwable);
  }
}
