package org.example;

import net.i2p.I2PException;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.data.DataFormatException;
import net.i2p.data.Destination;
import org.bouncycastle.cms.CMSSignedData;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    public static I2PSocket socket;
    public static void main(String[] args) throws Exception {
        String text = "Client Credentials";
        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        System.out.println("Please enter a Destination:");
//        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        Scanner in = new Scanner(System.in);
        String destinationString;
        destinationString = in.nextLine();
        Destination destination;
        try {
            destination = new Destination(destinationString);
        } catch (DataFormatException ex) {
            System.out.println("Destination string incorrectly formatted.");
            return;
        }

//        I2PSocket socket;
        try {
            socket = manager.connect(destination);
        } catch (I2PException ex) {
            System.out.println("General I2P exception occurred!");
            return;
        } catch (ConnectException ex) {
            System.out.println("Failed to connect!");
            return;
        } catch (NoRouteToHostException ex) {
            System.out.println("Couldn't find host!");
            return;
        } catch (InterruptedIOException ex) {
            System.out.println("Sending/receiving was interrupted!");
            return;
        }
        transferFileClient t = new transferFileClient(socket);
        CMSSignedData signedData = SignMessage.getSignature(text,"keys/server.p12","PKCS12","admin","key2");
//        System.out.println(signedData.getSignedContent());
        File f = new File("Signature/TE.sign");
        FileOutputStream fout = new FileOutputStream(f);
        fout.write(signedData.getEncoded());
        fout.close();
        try {
            t.getTEKeys();
            t.displayMenu();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
