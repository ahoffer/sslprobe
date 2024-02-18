package org.hoffer.sslprobe;

import java.io.*;
import java.net.*;

class Server {

  final ServerSocket serverSocket;
  final String response;

  public Server(ServerSocket ss, String response) {
    serverSocket = ss;
    this.response = response;
  }

  // Accept one connection, write a string, and close the socket
  public void start() {

    // Run server in its own thread because socket.accept() is blocking
    new Thread(this::runForever).start();
  }

  void runForever() {
    while (true) {
      Socket socket;
      try {
        socket = serverSocket.accept();
        OutputStream rawOut = socket.getOutputStream();
        PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(rawOut)));
        out.println(response);
        out.flush();
        socket.close();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
