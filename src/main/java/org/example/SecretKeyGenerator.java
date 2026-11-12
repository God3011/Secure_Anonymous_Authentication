package org.example;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;

public class SecretKeyGenerator {
    public static SecretKey generateSecretKey(PrivateKey pvt, PublicKey PublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH","BC");
        keyAgreement.init(pvt);
        keyAgreement.doPhase(PublicKey,true);

        SecretKey key = keyAgreement.generateSecret("AES");
        byte[] sec = key.getEncoded();
//        System.out.println("Generated Secret Key : " + toHex(sec));
        return key;
    }
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b: data) {
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }
}
