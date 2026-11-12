package org.example.transferfileservices;

import net.i2p.I2PException;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import org.bouncycastle.pkcs.PKCSException;
import org.example.keygenerator.KeyGenerator;
import org.example.keygenerator.SecretKeyGenerator;
import org.example.RC;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class transferFile implements Runnable {
    private I2PServerSocket socket;
    I2PSocket ClientSoc;
    DataInputStream din;
    DataOutputStream dout;
    Cipher cipher;
    SecretKey secretKeyA, secretKeyB;
    KeyPair keyPair;
    PublicKey pub, tePublicKey, mecsPublicKey;
    PrivateKey pvt;
    transferFileClient te;
    transferFileClient2 mecs;
    SecureRandom random = new SecureRandom();
    public static byte[] iv = new byte[16];

    public transferFile(I2PServerSocket socket) throws I2PException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, ClassNotFoundException, InvalidAlgorithmParameterException, InterruptedException, InvalidKeyException, PKCSException {
        this.socket = socket;
        ClientSoc = this.socket.accept();
        din = new DataInputStream(ClientSoc.getInputStream());
        dout = new DataOutputStream(ClientSoc.getOutputStream());
        System.out.println("Connected...");
        keyPair = org.example.keygenerator.KeyGenerator.generateRCKeys();
        pub = keyPair.getPublic();
        pvt = keyPair.getPrivate();
        System.out.println("RC Public Key : " + org.example.keygenerator.KeyGenerator.toHex(pub.getEncoded()));
        System.out.println("RC Private Key : " + org.example.keygenerator.KeyGenerator.toHex(pvt.getEncoded()));

    }

    public void initializeTE() {
        try {
            dout.writeUTF("Signature Verified");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            tePublicKey = org.example.keygenerator.KeyGenerator.generateTEKeys().getPublic();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | PKCSException e) {
            throw new RuntimeException(e);
        }
        try {
            secretKeyA = SecretKeyGenerator.generateSecretKey(pvt, tePublicKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        System.out.println("TE Public Key : " + org.example.keygenerator.KeyGenerator.toHex(tePublicKey.getEncoded()));
        System.out.println("Generated TE Secret Key : " + org.example.keygenerator.KeyGenerator.toHex(secretKeyA.getEncoded()));
    }

    public void initializeMECS() {
        try {
            dout.writeUTF("Signature Verified");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            mecsPublicKey = org.example.keygenerator.KeyGenerator.generateMECSKeys().getPublic();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | PKCSException e) {
            throw new RuntimeException(e);
        }
        try {
            secretKeyB = SecretKeyGenerator.generateSecretKey(pvt, mecsPublicKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        System.out.println("MECS Public Key : " + org.example.keygenerator.KeyGenerator.toHex(mecsPublicKey.getEncoded()));
        System.out.println("Generated MECS Secret Key : " + KeyGenerator.toHex(secretKeyB.getEncoded()));

    }

    @Override
    public void run() {
        if (RC.t.getName().compareTo("clienthandler1") == 0) {
            initializeTE();
        }
        if (RC.t.getName().compareTo("clienthandler2") == 0) {
            initializeMECS();
        }

        while (true) {
            try {
                String command = din.readUTF();
                if (command.compareTo("TE Send") == 0) {
                    System.out.println("TE Sending File\n");
                    receiveTEFile();
                    continue;
                } else if (command.compareTo("TE Receive") == 0) {
                    System.out.println("Sending File to TE\n");
                    sendTEFile();
                    continue;
                } else if (command.compareTo("MECS Send") == 0) {
                    System.out.println("MECS Sending File\n");
                    receiveMECSFile();
                    continue;

                } else if (command.compareTo("MECS Receive") == 0) {
                    System.out.println("Sending File to MECS\n");
                    sendMECSFile();
                    continue;

                } else if (command.compareTo("TE Exit") == 0) {
                    System.out.println("TE Exiting...");
                    System.exit(1);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void sendMECSFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String filename = din.readUTF();
        File f = new File(filename);
        if (!f.exists()) {
            dout.writeUTF("File Not Found");
            return;
        } else {
            dout.writeUTF("READY");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyB, ivSpec);
            FileInputStream fin = new FileInputStream(f);
            byte[] inputbytes = new byte[(int) f.length()];
            fin.read(inputbytes);
            byte[] outputBytes = cipher.doFinal(inputbytes);
            FileOutputStream out = new FileOutputStream("ex.enc");

            out.write(iv, 0, 16);
            out.write(outputBytes);
            fin.close();
            out.close();

            dout.writeUTF("File Receive Successfully");

        }

    }

    private void receiveMECSFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String filename = din.readUTF();
        if (filename.compareTo("File not found") == 0) {
            return;
        }
        File f = new File(filename);
        String option;
        if (f.exists()) {
            dout.writeUTF("File Already Exists");
            option = din.readUTF();
        } else {
            dout.writeUTF("SendFile");
            option = "Y";
        }

        if (option.compareTo("Y") == 0) {
            IvParameterSpec ivSpec;
            File f1 = new File("ex.enc");
            FileInputStream fin = new FileInputStream(f1);
            byte[] inputbytes = new byte[(int) f1.length()];
            fin.read(inputbytes);
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            ivSpec = new IvParameterSpec(inputbytes, 0, 16);
            cipher.init(Cipher.DECRYPT_MODE, secretKeyB, ivSpec);
            byte[] outputBytes = cipher.doFinal(Arrays.copyOfRange(inputbytes, 16, inputbytes.length));
            File f2 = new File("output.txt");
            FileOutputStream fout = new FileOutputStream(f2);
            fout.write(outputBytes);
            fin.close();
            fout.close();
            dout.writeUTF("File Send Successfully");
        } else {
            return;
        }
    }


    private void receiveTEFile() throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InterruptedException {
        String filename = din.readUTF();
        if (filename.compareTo("File not found") == 0) {
            return;
        }
        File f = new File(filename);
        String option;
        if (f.exists()) {
            dout.writeUTF("File Already Exists");
            option = din.readUTF();
        } else {
            dout.writeUTF("SendFile");
            option = "Y";
        }

        if (option.compareTo("Y") == 0) {
            IvParameterSpec ivSpec;
            byte iv[] = din.readNBytes(16);
            int len = din.readInt();
            byte[] inputbytes = din.readNBytes(len);
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            ivSpec = new IvParameterSpec(iv, 0, 16);
            cipher.init(Cipher.DECRYPT_MODE, secretKeyA, ivSpec);
            byte[] outputBytes = cipher.doFinal(inputbytes);
            File f2 = new File("output.txt");
            FileOutputStream fout = new FileOutputStream(f2);
            fout.write(outputBytes);
            fout.close();
            dout.writeUTF("File Send Successfully");
        } else {
            return;
        }
    }

    public void sendTEFile() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String filename = din.readUTF();
        File f = new File(filename);
        if (!f.exists()) {
            dout.writeUTF("File Not Found");
            return;
        } else {
            dout.writeUTF("READY");
            random.nextBytes(iv);
            dout.flush();
            dout.write(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyA, ivSpec);
            FileInputStream fin = new FileInputStream(f);
            byte[] inputbytes = new byte[(int) f.length()];
            fin.read(inputbytes);
            byte[] outputBytes = cipher.doFinal(inputbytes);
            dout.writeInt(outputBytes.length);
            dout.write(outputBytes);
            fin.close();
            dout.writeUTF("File Receive Successfully");

        }
    }

}
