package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;

public class AES
{
    byte[] keyBytes;
    private Cipher cipher;
    private SecretKeySpec key;
    private IvParameterSpec iv;

    public AES()
    {

        try
        {
            //沒加這行會有error --> no such provider:BC
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public void createKey(byte[] keyBytes, BigInteger iv)
    {
        this.keyBytes = keyBytes;
        this.key = new SecretKeySpec(keyBytes, "AES");
        //new BigInteger(128, new SecureRandom())
        this.iv = new IvParameterSpec(iv.toByteArray());
    }

    public byte[] encrypt(byte[] plainText)
    {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return cipher.doFinal(plainText);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decrypt(byte[] cipherText)
    {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(cipherText);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }
}

