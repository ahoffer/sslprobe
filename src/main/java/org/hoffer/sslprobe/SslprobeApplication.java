package org.hoffer.sslprobe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.shell.command.annotation.CommandScan;

@SpringBootApplication
@CommandScan
public class SslprobeApplication {

  public static void main(String[] args) {

    SpringApplication.run(SslprobeApplication.class, args);
  }
}
