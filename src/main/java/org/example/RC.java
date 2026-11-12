package org.example;

import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.util.I2PThread;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.example.digitalsignature.verifyMessage;
import org.example.transferfileservices.transferFile;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

public class RC {
    public static I2PThread t = null;
    static I2PThread t1 = null;
    static boolean te = false;
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, PKCSException, I2PException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, ClassNotFoundException, InterruptedException, CMSException, CertificateException, OperatorCreationException {

        I2PSocketManager manager = I2PSocketManagerFactory.createManager();
        I2PServerSocket serverSocket = manager.getServerSocket();
        I2PSession session = manager.getSession();
        System.out.println(session.getMyDestination().toBase64());

        //Create socket to handle clients
        t = new I2PThread(new transferFile(serverSocket));
        TimeUnit.SECONDS.sleep(1);
        File f = new File("Signature/TE.sign");
        FileInputStream fin = new FileInputStream(f);
        byte[] encoded = new byte[(int) f.length()];
        fin.read(encoded);
        CMSSignedData signedData = new CMSSignedData(encoded);
        boolean auth = verifyMessage.verifySignature(signedData);

        if(auth){
            t.setName("clienthandler1");
            t.setDaemon(false);
            te = true;
            t.start();
        }
        else{
            System.out.println("Not a verified user");
            t.stop();
            System.exit(1);
        }

        t = new I2PThread(new transferFile(serverSocket));
        TimeUnit.SECONDS.sleep(1);
        File f1 = new File("Signature/MECS.sign");
        FileInputStream fin1 = new FileInputStream(f1);
        byte[] encoded1 = new byte[(int) f1.length()];
        fin1.read(encoded1);
        CMSSignedData signedData1 = new CMSSignedData(encoded1);
        boolean auth1 = verifyMessage.verifySignature(signedData1);
        if(auth1){
            t.setName("clienthandler2");
            t.setDaemon(false);
            t.start();
        }
        else{
            System.out.println("Not a verified user");
            t1.stop();
            System.exit(1);
        }
    }
}
