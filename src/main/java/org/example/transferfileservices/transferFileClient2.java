package org.example.transferfileservices;

import net.i2p.client.streaming.I2PSocket;
import org.bouncycastle.pkcs.PKCSException;
import org.example.keygenerator.KeyGenerator;
import org.example.keygenerator.SecretKeyGenerator;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;

public class transferFileClient2 {
    I2PSocket ClientSoc;
    DataInputStream din;
    DataOutputStream dout;
    KeyPair kp;
    PublicKey pub,recPublickey;
    PrivateKey pvt;
    SecretKey secretKey;
    Cipher cipher;
    public static byte[] iv = new SecureRandom().generateSeed(16);
    public transferFileClient2(I2PSocket soc) throws IOException {
        try {
            ClientSoc = soc;
            din = new DataInputStream(ClientSoc.getInputStream());
            dout = new DataOutputStream(ClientSoc.getOutputStream());
            System.out.println("Connected...");
        }
        catch(Exception ex)
        {}
    }

    public void getMECSKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException, NoSuchProviderException, InvalidKeyException {
        String msg = din.readUTF();
        if(msg.compareTo("Signature Verified") == 0){
            System.out.println("Verified!");
            kp = org.example.keygenerator.KeyGenerator.generateMECSKeys();
            pub = kp.getPublic();
            pvt = kp.getPrivate();
            recPublickey = org.example.keygenerator.KeyGenerator.generateRCKeys().getPublic();
            secretKey = SecretKeyGenerator.generateSecretKey(pvt,recPublickey);
            System.out.println("MECS Public Key : " + org.example.keygenerator.KeyGenerator.toHex(pub.getEncoded()));
            System.out.println("MECS Private Key : " + org.example.keygenerator.KeyGenerator.toHex(pvt.getEncoded()));
            System.out.println("RC Public Key : " + org.example.keygenerator.KeyGenerator.toHex(recPublickey.getEncoded()));
            System.out.println("Generated Secret Key : " + KeyGenerator.toHex(secretKey.getEncoded()));
        }
        else{
            System.out.println("Invalid Signature");
        }
    }
    void receiveFile() throws Exception
    {
        Scanner in = new Scanner(System.in);
        String fileName;
        System.out.print("Enter File Name :");
        fileName=in.nextLine();
        dout.writeUTF(fileName);
        String msgFromServer=din.readUTF();

        if(msgFromServer.compareTo("File Not Found")==0)
        {
            System.out.println("File not found on Server ...");
            return;
        }
        else if(msgFromServer.compareTo("READY")==0)
        {
            System.out.println("Receiving File ...");
            File f=new File(fileName);
            if(f.exists())
            {
                String Option;
                System.out.println("File Already Exists. Want to OverWrite (Y/N) ?");
                Option=in.nextLine();
                if(Option=="N")
                {
                    dout.flush();
                    return;
                }
            }

            IvParameterSpec ivSpec;
            File f1 = new File("ex.enc");
            FileInputStream fin = new FileInputStream(f1);
            byte[] inputbytes = new byte[(int) f1.length()];
            fin.read(inputbytes);
            cipher = Cipher.getInstance("AES/GCM/NoPadding","BC");
            byte[] iv = Arrays.copyOfRange(inputbytes,0,16);
            ivSpec = new IvParameterSpec(inputbytes,0,16);
            cipher.init(Cipher.DECRYPT_MODE,secretKey,ivSpec);
            byte[] outputBytes = cipher.doFinal(Arrays.copyOfRange(inputbytes,16, inputbytes.length));

            File f2 = new File("output.txt");
            FileOutputStream fout=new FileOutputStream(f2);
            fout.write(outputBytes);
            fin.close();
            fout.close();
            System.out.println(din.readUTF());
        }
    }
    private void sendFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Scanner in = new Scanner(System.in);
        String filename;
        System.out.print("Enter File Name :");
        filename=in.nextLine();

        File f=new File(filename);
        if(!f.exists())
        {
            System.out.println("File not Exists...");
            dout.writeUTF("File not found");
            return;
        }

        dout.writeUTF(filename);
        String msgFromServer=din.readUTF();
        if(msgFromServer.compareTo("File Already Exists")==0)
        {
            String Option;
            System.out.println("File Already Exists. Want to OverWrite (Y/N) ?");
            Option=in.nextLine();
            if(Option.compareTo("Y") == 0)
            {
                dout.writeUTF("Y");
            }
            else
            {
                dout.writeUTF("N");
                return;
            }
        }

        System.out.println("Sending File ...");

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES/GCM/NoPadding","BC");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivSpec);
        FileInputStream fin=new FileInputStream(f);
        byte[] inputbytes = new byte[(int) f.length()];
        fin.read(inputbytes);
        byte[] outputBytes = cipher.doFinal(inputbytes);
        FileOutputStream out = new FileOutputStream("ex.enc");

        out.write(iv,0,16);
        out.write(outputBytes);
        fin.close();
        out.close();
        System.out.println(din.readUTF());

    }

    public void displayMenu() throws Exception {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println("[ MENU ]");
            System.out.println("1. Send File");
            System.out.println("2. Receive File");
            System.out.println("3. Exit");
            System.out.print("\nEnter Choice :");
            int choice;
            choice = Integer.parseInt(in.nextLine());
            if (choice == 1) {
                dout.writeUTF("MECS Send");
                sendFile();
            } else if (choice == 2) {
                dout.writeUTF("MECS Receive");
                receiveFile();
            } else {
                dout.writeUTF("MECS Exit");
                dout.flush();
                System.exit(1);
            }
        }
    }
}
