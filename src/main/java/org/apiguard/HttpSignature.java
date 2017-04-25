package org.apiguard;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apiguard.crypto.Algorithm;
import org.apiguard.crypto.exception.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HttpSignature {

    /**
     * Create a base64 HMAC signature
     * @param secret
     * @param stringToSign
     * @param algorithm
     * @return
     */
    public static String signWithBase64(String secret, String stringToSign, Algorithm algorithm) throws CryptoException {
        try {
            if (algorithm.getRefClass().getName().equals(Mac.class.getName())) {
                byte[] data = getSignBytes(secret, stringToSign, algorithm);
                return Base64.encodeBase64String(data);
            }
            else {
                throw new CryptoException("Unsupported algorithm: " + algorithm.getId());
            }
        }
        catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }


    public static String signWithHex(String secret, String stringToSign, Algorithm algorithm) throws CryptoException {
        try {
            if (algorithm.getRefClass().getName().equals(Mac.class.getName())) {
                byte[] data = getSignBytes(secret, stringToSign, algorithm);
                return Hex.encodeHexString(data);
            }
            else {
                throw new CryptoException("Unsupported algorithm: " + algorithm.getId());
            }
        }
        catch (Exception e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    private static byte[] getSignBytes(String secret, String stringToSign, Algorithm algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Mac hmac = Mac.getInstance(algorithm.getId());
        SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), algorithm.getId());
        hmac.init(secret_key);

        return hmac.doFinal(stringToSign.getBytes("UTF-8"));
    }
}
