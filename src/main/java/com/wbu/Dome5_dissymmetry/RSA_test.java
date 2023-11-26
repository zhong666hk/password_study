package com.wbu.Dome5_dissymmetry;


import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.FileUtil;

import javax.crypto.Cipher;
import java.io.File;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA_test {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    //定义路径
    private static String publicPath = "publicKey.txt";
    private static String privatePath = "privateKey.txt";

    public static void main(String[] args) throws Exception {
        // 原文
        String input = "钟";
        // 算法
        String algorithm = "RSA";
        // 判断文件是否存在，来判断要不要生成密钥
        if (new File(publicPath).exists() && new File(privatePath).exists()) {
            privateKey = getPrivateKey(algorithm, privatePath);
            publicKey = getPublicKey(algorithm, publicPath);
        } else {
            generatorKey(algorithm);
        }

        // 加密
        byte[] bytes = RSA_ENCRYPT(algorithm, input);
        System.out.println("加密后\t" + Base64.encode(bytes));
        // 解密
        byte[] bytes1 = RAS_DECRYPT(algorithm, bytes);
        System.out.println("加密后\t" + new String(bytes1));
    }

    /**
     * 读取私钥
     *
     * @param algorithm 算法
     * @param path      文件路径
     */
    public static PrivateKey getPrivateKey(String algorithm, String path) throws Exception {
        // 读取私钥
        String privateKeyString = FileUtil.readString(new File(path), "UTF-8");
        // 创建钥匙工厂
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString));
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 读取公钥
     *
     * @param algorithm 算法
     * @param path      文件路径
     */
    public static PublicKey getPublicKey(String algorithm, String path) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 读取私钥
        String publicKeyString = FileUtil.readString(new File(path), "UTF-8");
        // 创建钥匙工厂
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKeyString));
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 解密
     *
     * @param algorithm 算法
     * @param bytes     密文
     */
    private static byte[] RAS_DECRYPT(String algorithm, byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(bytes);
    }

    /**
     * 加密
     *
     * @param algorithm 算法
     * @param input     原文
     */
    private static byte[] RSA_ENCRYPT(String algorithm, String input) throws Exception {
        // 加密
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(input.getBytes());
        return bytes;
    }

    /**
     * 生成私钥和公钥 并且存储到更目录中
     *
     * @param algorithm 算法
     */
    private static void generatorKey(String algorithm) throws NoSuchAlgorithmException {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 生成公钥和私钥
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        // 将密码写入文件
        FileUtil.writeString(Base64.encode(publicKey.getEncoded()), new File(publicPath), "UTF-8");
        FileUtil.writeString(Base64.encode(privateKey.getEncoded()), new File(privatePath), "UTF-8");
    }
}
