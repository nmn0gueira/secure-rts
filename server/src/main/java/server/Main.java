package server;

/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import common.datagram.SecureDatagramSocket;

import java.io.*;
import java.net.*;

public class Main {

	static void main(String[] args) throws Exception {
		if (args.length != 4)
		{
			System.out.println("Usage: mySend <movie> <ip-multicast-address> <port> [<encryption-alg>]");
			System.out.println("Encryption algorithm defaults to AES-GCM. Available options:");
			System.out.println("aes - AES-GCM");
			System.out.println("chacha - ChaCha20-Poly1305");
			System.out.println("dprg - Custom stream cipher from keystream generation based on AES-CTR");
		   	System.exit(-1);
		}
		int size;
		int csize = 0;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
		byte[] buff = new byte[4096];

		SecureDatagramSocket s = new SecureDatagramSocket(args[3]);
		InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(); // Ref. time 
		long q0 = 0;


		// Movies are encoded in .dat files, where each
		// frame is encoded in a real-time sequence of MP4 frames
		// Somewhat an FFMPEG4 playing scheme .. Dont worry
		
		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame
		// You can read (frame by frame to transmit ...
		// But you must folow the "real-time" encoding conditions

		// OK let's do it !

		while ( g.available() > 0 ) {
		    
		    size = g.readShort(); // size of the frame
		    csize = csize + size;
		    time = g.readLong();  // timestamp of the frame
			if (count == 0) q0 = time; // ref. time in the stream
			count += 1;
			g.readFully(buff, 0, size);
			p.setData(buff, 0, size);
			p.setSocketAddress( addr );

			long t = System.nanoTime(); // what time is it?

			// Decision about the right time to transmit
			Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));
		   
			// send datagram (udp packet) w/ payload frame)
			// Frames sent in clear (no encryption)
			s.send(p); 

			// Just for awareness ... (debug)
			System.out.print( ":" );
		}

		long tend = System.nanoTime(); // "The end" time 
		System.out.println();
		System.out.println("DONE! all frames sent: "+ count);

		long duration=(tend-t0)/1000000000;
		System.out.println("Movie duration "+ duration + " s");
		System.out.println("Throughput "+ count/duration + " fps");
		System.out.println("Throughput "+ (8L * (csize) / duration) / 1000 + " Kbps");

	}
}



