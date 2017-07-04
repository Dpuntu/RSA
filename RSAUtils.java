import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;

/**
 * 非对称加密
 * Created by Dpuntu on 2017/6/16.
 * <p>
 * 参考 ：
 * <p>
 * http://blog.csdn.net/u012427018/article/details/50723000
 * <p>
 * http://blog.csdn.net/defonds/article/details/42775183
 */

public class RSAUtils {

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;
    private static HashMap<String, Object> map;

    /**
     * 初始化公钥私钥
     */
    public static HashMap<String, Object> initKeys()
            throws NoSuchAlgorithmException {
        if (map != null) {
            map.clear();
            map = null;
        }
        map = new HashMap<>();
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        setPublicKey((RSAPublicKey) keyPair.getPublic());
        setPrivateKey((RSAPrivateKey) keyPair.getPrivate());

        map.put("public", getPublicKey());
        map.put("private", getPrivateKey());

        return map;
    }

    /**
     * 获得公钥
     *
     * @return String Base64公钥
     */
    public static String getStringPublicKey() {
        return Base64.encodeToString(getPublicKey(map), Base64.DEFAULT);
    }

    /**
     * 获得私钥
     *
     * @return String Base64私钥
     */
    public static String getStringPrivateKey() {
        return Base64.encodeToString(getPrivateKey(map), Base64.DEFAULT);
    }

    /**
     * 取得私钥
     *
     * @return byte[] 私钥
     */
    private static byte[] getPrivateKey(HashMap<String, Object> map) {
        Key key = (Key) map.get("private");
        return key.getEncoded();
    }

    /**
     * 取得公钥
     *
     * @return byte[] 公钥
     */
    private static byte[] getPublicKey(HashMap<String, Object> map) {
        Key key = (Key) map.get("public");
        return key.getEncoded();
    }

    private static RSAPublicKey getPublicKey() {
        return publicKey;
    }

    private static void setPublicKey(RSAPublicKey publicKey) {
        RSAUtils.publicKey = publicKey;
    }

    public static RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    private static void setPrivateKey(RSAPrivateKey privateKey) {
        RSAUtils.privateKey = privateKey;
    }

    /**
     * 解密
     *
     * @param encryptedBytes
     *         byte[] 待解密数据
     * @param privateKey
     *         PrivateKey 私钥
     *
     * @return String 解密结果
     */
    public static String decrypt(byte[] encryptedBytes, PrivateKey privateKey) throws Exception {
        return new String(decrypt(encryptedBytes, privateKey, 2048, 11, "RSA/ECB/PKCS1Padding"));
    }

    /**
     * 加密
     *
     * @param plainBytes
     *         byte[] 待加密数据
     * @param publicKey
     *         PublicKey 公钥
     *
     * @return String 解密结果
     */
    public static String encrypt(byte[] plainBytes, PublicKey publicKey) throws Exception {
        return new String(encrypt(plainBytes, publicKey, 2048, 11, "RSA/ECB/PKCS1Padding"));
    }

    /**
     * 解密
     *
     * @param encryptedBytes
     *         byte[] 解密后的字节数组
     * @param privateKey
     *         PrivateKey 私钥
     * @param keyLength
     *         int 密钥bit长度
     * @param reserveSize
     *         int  padding填充字节数，预留11字节
     * @param cipherAlgorithm
     *         String 加解密算法，一般为RSA/ECB/PKCS1Padding
     *
     * @return String 解密结果
     */
    public static byte[] decrypt(byte[] encryptedBytes, PrivateKey privateKey,
                                 int keyLength, int reserveSize, String cipherAlgorithm)
            throws Exception {
        int keyByteSize = keyLength / 8;
        int decryptBlockSize = keyByteSize - reserveSize;
        int nBlock = encryptedBytes.length / keyByteSize;
        ByteArrayOutputStream outbuf = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            outbuf = new ByteArrayOutputStream(nBlock * decryptBlockSize);
            for (int offset = 0; offset < encryptedBytes.length; offset += keyByteSize) {
                int inputLen = encryptedBytes.length - offset;
                if (inputLen > keyByteSize) {
                    inputLen = keyByteSize;
                }
                byte[] decryptedBlock = cipher.doFinal(encryptedBytes, offset,
                                                       inputLen);
                outbuf.write(decryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            throw new Exception("DEENCRYPT ERROR:", e);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);
            }
        }
    }

    /**
     * 加密
     *
     * @param plainBytes
     *         byte[] 加密后的字节数组
     * @param publicKey
     *         publicKey 公钥
     * @param keyLength
     *         int 密钥bit长度
     * @param reserveSize
     *         int  padding填充字节数，预留11字节
     * @param cipherAlgorithm
     *         String 加解密算法，一般为RSA/ECB/PKCS1Padding
     *
     * @return String 解密结果
     */
    public static byte[] encrypt(byte[] plainBytes, PublicKey publicKey,
                                 int keyLength, int reserveSize, String cipherAlgorithm)
            throws Exception {
        int keyByteSize = keyLength / 8;
        int encryptBlockSize = keyByteSize - reserveSize;
        int nBlock = plainBytes.length / encryptBlockSize;
        if ((plainBytes.length % encryptBlockSize) != 0) {
            nBlock += 1;
        }
        ByteArrayOutputStream outbuf = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            outbuf = new ByteArrayOutputStream(nBlock * keyByteSize);
            for (int offset = 0; offset < plainBytes.length; offset += encryptBlockSize) {
                int inputLen = plainBytes.length - offset;
                if (inputLen > encryptBlockSize) {
                    inputLen = encryptBlockSize;
                }
                byte[] encryptedBlock = cipher.doFinal(plainBytes, offset,
                                                       inputLen);
                outbuf.write(encryptedBlock);
            }
            outbuf.flush();
            return outbuf.toByteArray();
        } catch (Exception e) {
            throw new Exception("ENCRYPT ERROR:", e);
        } finally {
            try {
                if (outbuf != null) {
                    outbuf.close();
                }
            } catch (Exception e) {
                outbuf = null;
                throw new Exception("CLOSE ByteArrayOutputStream ERROR:", e);
            }
        }
    }

    public static PrivateKey getPriKey(String privateKeyPath,
                                       String keyAlgorithm) {
        PrivateKey privateKey = null;
        InputStream inputStream = null;
        try {
            if (inputStream == null) {
            }
            inputStream = new FileInputStream(privateKeyPath);
            privateKey = getPrivateKey(inputStream, keyAlgorithm);
        } catch (Exception e) {
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e) {
                }
            }
        }
        return privateKey;
    }

    public static PublicKey getPubKey(String publicKeyPath, String keyAlgorithm) {
        PublicKey publicKey = null;
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(publicKeyPath);
            publicKey = getPublicKey(inputStream, keyAlgorithm);
        } catch (Exception e) {
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e) {
                }
            }
        }
        return publicKey;
    }

    public static PublicKey getPublicKey(InputStream inputStream,
                                         String keyAlgorithm) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    inputStream));
            StringBuilder sb = new StringBuilder();
            String readLine = null;
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(
                    decodeBase64(sb.toString()));
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PublicKey publicKey = keyFactory.generatePublic(pubX509);

            return publicKey;
        } catch (Exception e) {
            throw new Exception("READ PUBLIC KEY ERROR:", e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                inputStream = null;
                throw new Exception("INPUT STREAM CLOSE ERROR:", e);
            }
        }
    }

    public static PrivateKey getPrivateKey(InputStream inputStream,
                                           String keyAlgorithm) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    inputStream));
            StringBuilder sb = new StringBuilder();
            String readLine = null;
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
                    decodeBase64(sb.toString()));
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
            return privateKey;
        } catch (Exception e) {
            throw new Exception("READ PRIVATE KEY ERROR:", e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                inputStream = null;
                throw new Exception("INPUT STREAM CLOSE ERROR:", e);
            }
        }
    }

    public static String encodeBase64(byte[] input) throws Exception {
        Class clazz = Class
                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod = clazz.getMethod("encode", byte[].class);
        mainMethod.setAccessible(true);
        Object retObj = mainMethod.invoke(null, new Object[] {input});
        return (String) retObj;
    }


    public static byte[] decodeBase64(String input) throws Exception {
        Class clazz = Class
                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod = clazz.getMethod("decode", String.class);
        mainMethod.setAccessible(true);
        Object retObj = mainMethod.invoke(null, input);
        return (byte[]) retObj;
    }
}
