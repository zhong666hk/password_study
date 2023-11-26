package com.wbu.Dome3_symmetry;

import cn.hutool.core.codec.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class AES {
    public static void main(String[] args) throws Exception {
        // 定义原文
        String input ="钟";
        //定义key --->des加密key必需为8位
        String key ="1234567812345678";
        // 定义加密算法 "AES/CBC/PKCS5Padding"
        String transformation ="AES";
        // 加密类型
        String algorithm="AES";

        String encode = encryptDES(transformation, key, algorithm, input);
        System.out.println("加密后\t"+encode);
        String decrypt = decryptDES(transformation, key, algorithm, encode);
        System.out.println("解密后\t"+decrypt);
    }

    /**
     * 解密DES
     * @param transformation 算法
     * @param key   key
     * @param algorithm 加密类型
     * @param secret 密文
     * @return  返回原文
     */
    private static String decryptDES(String transformation, String key, String algorithm, String secret) throws Exception {
        // 创建解密对象
        Cipher cipher = Cipher.getInstance(transformation);
        //创建解密规则
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(),algorithm);
        // 初始化对象
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);
        // 解密-->密文转码过了，必需解码
        byte[] bytes = cipher.doFinal(Base64.decode(secret));
        return new String(bytes);
    }

    /**
     * 加密 DES
     * @param transformation 算法
     * @param key key
     * @param algorithm 加密类型
     * @param input 原文
     */
    private static String encryptDES(String transformation, String key, String algorithm, String input) throws Exception  {
        // 创建加密对象 1.加密算法
        Cipher cipher = Cipher.getInstance(transformation);
        // 创建加密规则 1.表示key的字节 2.表示加密的类型
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        // 初始化 1.模式：加密、解密 模式 2.加密规则、解密规则
        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
        // 完成加密或者解密
        byte[] bytes = cipher.doFinal(input.getBytes());
        // 必需使用base64进行转码。不然会乱码
        String encode = Base64.encode(bytes);
        return encode;
    }
}
