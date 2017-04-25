package org.apiguard;

import org.apiguard.crypto.Algorithm;
import org.apiguard.crypto.exception.CryptoException;

import javax.crypto.Mac;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class DigitalSignatures {

    public static String sign(String privateKeyFile, String data, Algorithm algorithm) throws CryptoException {
        return sign(privateKeyFile, null, data, algorithm);
    }

    private static String sign(String privateKeyFile, String provider, String data, Algorithm algorithm) throws CryptoException {
        try {
            if (algorithm.getRefClass().getName().equals(Signature.class.getName())) {
                byte[] keyBytes = Files.readAllBytes(new File(privateKeyFile).toPath());
                X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(keyBytes);

                String type = algorithm.getName().startsWith("dsa") ? "DSA" : "RSA";
                KeyFactory keyFactory = null;
                if (provider == null) {
                    keyFactory = KeyFactory.getInstance(type);
                }
                else {
                    keyFactory = KeyFactory.getInstance(type, provider);
                }
                PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

                /* create a Signature object and initialize it with the public key */
                Signature sig = null;
                if (provider == null) {
                    sig = Signature.getInstance(algorithm.getId());
                }
                else {
                    sig = Signature.getInstance(algorithm.getId(), provider);
                }
                sig.initSign(privateKey, new SecureRandom());
                sig.update(data.getBytes());
                return new String(sig.sign());
            }
            else {
                throw new CryptoException("Unsupported algorithm: " + algorithm.getId());
            }
        }
        catch(Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }

    }

    public static boolean verify(String publicKeyFile, String signature, String data, Algorithm algorithm) throws CryptoException {
        return verify(publicKeyFile, null, signature, data, algorithm);
    }

    public static boolean verify(String publicKeyFile, String provider, String signature, String data, Algorithm algorithm) throws CryptoException {
        try {
            if (algorithm.getRefClass().getName().equals(Signature.class.getName())) {
                byte[] keyBytes = Files.readAllBytes(new File(publicKeyFile).toPath());
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBytes);

                String type = algorithm.getName().startsWith("dsa") ? "DSA" : "RSA";
                KeyFactory keyFactory = null;
                if (provider == null) {
                    keyFactory = KeyFactory.getInstance(type);
                }
                else {
                    keyFactory = KeyFactory.getInstance(type, provider);
                }
                PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

                byte[] sigToVerify = signature.getBytes();

                /* create a Signature object and initialize it with the public key */
                Signature sig = null;
                if (provider == null) {
                    sig = Signature.getInstance(algorithm.getId());
                }
                else {
                    sig = Signature.getInstance(algorithm.getId(), provider);
                }
                sig.initVerify(pubKey);

                /* Update and verify the data */
                sig.update(data.getBytes());
                return sig.verify(sigToVerify);
            }
            else {
                throw new CryptoException("Unsupported algorithm: " + algorithm.getId());
            }
        }
        catch(Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }
}
