package org.example.digitalsignature;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SignMessage {

//    static final String KEYSTORE_FILE = "keys/server.p12";
//    static final String KEYSTORE_INSTANCE = "PKCS12";
//    static final String KEYSTORE_PWD = "admin";
//    static final String KEYSTORE_ALIAS = "Key1";

    public static CMSSignedData getSignature(String text,String KEYSTORE_FILE,String KEYSTORE_INSTANCE,String KEYSTORE_PWD,String KEYSTORE_ALIAS) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
        Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());

        //Sign
        PrivateKey privKey = (PrivateKey) key;
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(privKey);
        signature.update(text.getBytes());

        //Build CMS
        X509Certificate cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(text.getBytes());
        certList.add(cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withECDSA").setProvider("BC").build(privKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(msg, true);
        return sigData;

    }

}