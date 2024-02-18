package org.hoffer.sslprobe;

import static org.springframework.shell.command.CommandRegistration.OptionArity.EXACTLY_ONE;
import static org.springframework.shell.command.CommandRegistration.OptionArity.ZERO_OR_ONE;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.jline.terminal.Terminal;
import org.springframework.shell.command.annotation.Command;
import org.springframework.shell.command.annotation.Option;

@Command
public class ProbeCommand {

  final Terminal terminal;

  public ProbeCommand(Terminal terminal) {
    this.terminal = terminal;
  }

  @Command
  public void probe(
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
          String port,
      @Option(
              description = "path to the truststore",
              shortNames = {'t'},
              arity = EXACTLY_ONE)
          String truststore,
      @Option(
              description = "path to the keystore",
              shortNames = {'k'},
              arity = ZERO_OR_ONE)
          String keystore,
      @Option(
              description = "common password",
              shortNames = {'w'},
              arity = ZERO_OR_ONE)
          String password)
      throws CertificateException,
          IOException,
          KeyStoreException,
          NoSuchAlgorithmException,
          UnrecoverableKeyException,
          KeyManagementException {
    try {

      Probe probe = new Probe(host, port, truststore, keystore, password);
      probe.probe();

    } catch (SslProbeException e) {
      terminal.writer().println(e.getMessage());
    }
  }
}
