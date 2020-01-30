package sise.cs.utils;

import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Signature {

    private AsymEncryptPriv asymEncryptPriv;
    private AsymDecryptPub asymDecryptPub;
    private MessageDigest digest;

    public Signature() throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.asymEncryptPriv = new AsymEncryptPriv();
        this.asymDecryptPub = new AsymDecryptPub();
        this.digest = MessageDigest.getInstance("SHA-256");
    }

    //generate signature
    public String sign(String message, String privateKeyFilename) throws Exception {
        PrivateKey privateKey = this.asymEncryptPriv.getPrivate(privateKeyFilename);
        String hash = buildHash(message);
        return this.asymEncryptPriv.encryptText(hash, privateKey);
    }

    //verify signature
    public boolean verify(String message, String digest, String publicKeyFilename) throws Exception {
        PublicKey publicKey = this.asymDecryptPub.getPublic(publicKeyFilename);
        String messageHash = buildHash(message);
        String digestHash = this.asymDecryptPub.decryptText(digest, publicKey);
        return messageHash.equals(digestHash);
    }

    private String buildHash(String message) throws UnsupportedEncodingException {
        return Base64.getEncoder().encodeToString(this.digest.digest(message.getBytes("UTF-8")));
    }

    public static void main(String[] args) throws Exception {
        //test: works!
        //vai ser avaliado: private key has to be secret
        Signature signature = new Signature();
        String digest = signature.sign("Hi hello", "keys/user2PrivateKey");
        System.out.println(signature.verify("Hi hello", digest, "keys/user2PublicKey"));
    }
}
