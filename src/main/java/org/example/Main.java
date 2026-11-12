package org.example;

import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.util.I2PThread;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Main {
    static I2PThread t = null;
    static I2PThread t1 = null;
    static SignMessage signMessage = null;
//    static transferFile te;
    static transferFile mecs;
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
//        System.out.println(signedData.getSignedContent());
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
//        System.out.println(signedData.getSignedContent());
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

//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//        File file = new File("Keys/public.pem");
//        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
//
//        String publicKeyPEM = key
//                .replace("-----BEGIN PUBLIC KEY-----", "")
//                .replaceAll(System.lineSeparator(), "")
//                .replace("-----END PUBLIC KEY-----", "");
//        byte[] publicKey = Base64.getDecoder().decode(publicKeyPEM);
//        KeyFactory keyFactory = KeyFactory.getInstance("EC");
//        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
//        PublicKey pub = keyFactory.generatePublic(x509EncodedKeySpec);
//        System.out.println(toHex(pub.getEncoded()));
//
//        File privateKeyFile = new File("Keys/private.pem"); // private key file in PEM format
//        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
//        Object o = pemParser.readObject();
//        PrivateKeyInfo pki;
//        String password = "admin";
//        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
//
//            PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;
//
//            JcePKCSPBEInputDecryptorProviderBuilder builder =
//                    new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");
//
//            InputDecryptorProvider idp = builder.build(password.toCharArray());
//
//            pki = epki.decryptPrivateKeyInfo(idp);
//        } else if (o instanceof PEMEncryptedKeyPair) {
//
//            PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
//            PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));
//
//            pki = pkp.getPrivateKeyInfo();
//        } else {
//            throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
//        }
//
//        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
//        PrivateKey pvt = converter.getPrivateKey(pki);
//        System.out.println(toHex(pvt.getEncoded()));

    }
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b: data) {
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }
}
