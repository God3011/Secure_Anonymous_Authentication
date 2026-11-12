package org.example.keygenerator;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyGenerator {
    public static KeyPair generateTEKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File file = new File("Keys/public_te.pem");
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] publicKey = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pub = keyFactory.generatePublic(x509EncodedKeySpec);

        File privateKeyFile = new File("Keys/private_te.pem"); // private key file in PEM format
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
        Object o = pemParser.readObject();
        PrivateKeyInfo pki;
        String password = "client1";
        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {

            PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;

            JcePKCSPBEInputDecryptorProviderBuilder builder =
                    new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");

            InputDecryptorProvider idp = builder.build(password.toCharArray());

            pki = epki.decryptPrivateKeyInfo(idp);
        } else if (o instanceof PEMEncryptedKeyPair) {

            PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
            PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));

            pki = pkp.getPrivateKeyInfo();
        } else {
            throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey pvt = converter.getPrivateKey(pki);
        return new KeyPair(pub,pvt);
    }
    public static KeyPair generateRCKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File file = new File("Keys/public.pem");
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] publicKey = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pub = keyFactory.generatePublic(x509EncodedKeySpec);

        File privateKeyFile = new File("Keys/private.pem"); // private key file in PEM format
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
        Object o = pemParser.readObject();
        PrivateKeyInfo pki;
        String password = "admin";
        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {

            PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;

            JcePKCSPBEInputDecryptorProviderBuilder builder =
                    new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");

            InputDecryptorProvider idp = builder.build(password.toCharArray());

            pki = epki.decryptPrivateKeyInfo(idp);
        } else if (o instanceof PEMEncryptedKeyPair) {

            PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
            PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));

            pki = pkp.getPrivateKeyInfo();
        } else {
            throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey pvt = converter.getPrivateKey(pki);

        return new KeyPair(pub,pvt);
    }
    public static KeyPair generateMECSKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, PKCSException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        File file = new File("Keys/public_mecs.pem");
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] publicKey = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pub = keyFactory.generatePublic(x509EncodedKeySpec);

        File privateKeyFile = new File("Keys/private_mecs.pem"); // private key file in PEM format
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
        Object o = pemParser.readObject();
        PrivateKeyInfo pki;
        String password = "client2";
        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {

            PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;

            JcePKCSPBEInputDecryptorProviderBuilder builder =
                    new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");

            InputDecryptorProvider idp = builder.build(password.toCharArray());

            pki = epki.decryptPrivateKeyInfo(idp);
        } else if (o instanceof PEMEncryptedKeyPair) {

            PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
            PEMKeyPair pkp = epki.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));

            pki = pkp.getPrivateKeyInfo();
        } else {
            throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey pvt = converter.getPrivateKey(pki);

        return new KeyPair(pub,pvt);
    }
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b: data) {
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }
}
