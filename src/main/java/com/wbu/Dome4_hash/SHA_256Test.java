package com.wbu.Dome4_hash;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.digest.Digester;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA_256Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 原文
        String input="aa";
        // 自带的MD5
        StringBuilder sb = originSHA256(input);
        System.out.println("originSHA256=\t"+sb);
        String hutoolSHA1 = hutoolSHA256(input);
        System.out.println("hutoolSHA256=\t"+hutoolSHA1);
    }
    private static StringBuilder originSHA256(String input) throws NoSuchAlgorithmException {
        // 算法
        String algorithm="SHA-256";
        // 创建消息摘要
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] digest1 = digest.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        //手动转码
        for (byte b : digest1) {
            // 去掉负数-->16进制
            String hexString = Integer.toHexString(b&0xff);
            if (hexString.length()==1){
                hexString="0"+hexString;
            }
            sb.append(hexString);
        }
        return sb;
    }

    public static String hutoolSHA256(String input) {
        Digester digester = SecureUtil.sha256();
        return digester.digestHex(input);
    }
}
