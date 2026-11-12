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

public class transferFileClient {
    I2PSocket ClientSoc;
    DataInputStream din;
    DataOutputStream dout;
    KeyPair kp;
    PublicKey pub,recPublickey;
    PrivateKey pvt;
    SecretKey secretKey;
    Cipher cipher;
    SecureRandom random = new SecureRandom();
    public static byte[] iv = new byte[16];
    public transferFileClient(I2PSocket soc) throws IOException {
        try {
            ClientSoc = soc;
            din = new DataInputStream(ClientSoc.getInputStream());
            dout = new DataOutputStream(ClientSoc.getOutputStream());
            System.out.println("Connected...");
        }
        catch(Exception ex)
        {}
    }

    public void getTEKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException, NoSuchProviderException, InvalidKeyException {
        String msg = din.readUTF();
        if(msg.compareTo("Signature Verified") == 0){
            System.out.println("Verified!");
            kp = org.example.keygenerator.KeyGenerator.generateTEKeys();
            pub = kp.getPublic();
            pvt = kp.getPrivate();
            recPublickey = org.example.keygenerator.KeyGenerator.generateRCKeys().getPublic();
            secretKey = SecretKeyGenerator.generateSecretKey(pvt,recPublickey);
            System.out.println("TE Public Key : " + org.example.keygenerator.KeyGenerator.toHex(pub.getEncoded()));
            System.out.println("TE Private Key : " + org.example.keygenerator.KeyGenerator.toHex(pvt.getEncoded()));
            System.out.println("RC Public Key : " + org.example.keygenerator.KeyGenerator.toHex(recPublickey.getEncoded()));
            System.out.println("Generated Secret Key : " + KeyGenerator.toHex(secretKey.getEncoded()));
        }
        else{
            System.out.println("Invalid Signature");
        }
    }

    public void displayMenu() throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InterruptedException {
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
                    dout.writeUTF("TE Send");
                    sendFile();
                } else if (choice == 2) {
                    dout.writeUTF("TE Receive");
                    receiveFile();
                } else {
                    dout.writeUTF("TE Exit");
                    dout.flush();
                    System.exit(1);
                }
        }
    }

    private void receiveFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Scanner in = new Scanner(System.in);
        String fileName;
        System.out.print("Enter File Name :");
        fileName = in.nextLine();
        dout.writeUTF(fileName);
        String msgFromServer = din.readUTF();

        if (msgFromServer.compareTo("File Not Found") == 0) {
            System.out.println("File not found on Server ...");
            return;
        } else if (msgFromServer.compareTo("READY") == 0) {
            System.out.println("Receiving File ...");
            File f = new File(fileName);
            if (f.exists()) {
                String Option;
                System.out.println("File Already Exists. Want to OverWrite (Y/N) ?");
                Option = in.nextLine();
                if (Option == "N") {
                    dout.flush();
                    return;
                }
            }

            IvParameterSpec ivSpec;
            byte iv[] = din.readNBytes(16);
            int len = din.readInt();
            System.out.println(Arrays.toString(iv) + " " + len);
            byte[] inputbytes = din.readNBytes(len);
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            ivSpec = new IvParameterSpec(iv, 0, 16);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] outputBytes = cipher.doFinal(inputbytes);

            File f2 = new File("output.txt");
            FileOutputStream fout = new FileOutputStream(f2);
            fout.write(outputBytes);
            fout.close();
        }
    }    

    public void sendFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
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

        random.nextBytes(iv);
        dout.write(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES/GCM/NoPadding","BC");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivSpec);
        FileInputStream fin=new FileInputStream(f);
        byte[] inputbytes = new byte[(int) f.length()];
        fin.read(inputbytes);
        byte[] outputBytes = cipher.doFinal(inputbytes);
        dout.writeInt(outputBytes.length);
        dout.write(outputBytes);
        fin.close();
        System.out.println(din.readUTF());
    }
}
