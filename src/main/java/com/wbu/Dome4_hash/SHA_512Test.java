package com.wbu.Dome4_hash;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.digest.Digester;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA_512Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 原文
        String input="aa";
        // 自带的MD5
        StringBuilder sb = originSHA512(input);
        System.out.println("originSHA512=\t"+sb);
    }
    private static StringBuilder originSHA512(String input) throws NoSuchAlgorithmException {
        // 算法
        String algorithm="SHA-512";
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
}
