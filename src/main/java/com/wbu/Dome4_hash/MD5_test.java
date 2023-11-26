package com.wbu.Dome4_hash;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.digest.MD5;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5_test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 原文
        String input="aa";
        // 自带的MD5
        StringBuilder sb = originMD5(input);
        System.out.println("originMD5=\t"+sb);
        String hutoolMD5 = hutoolMD5(input);
        System.out.println("hutoolMD5=\t"+hutoolMD5);
    }

    private static StringBuilder originMD5(String input) throws NoSuchAlgorithmException {
        // 算法
        String algorithm="MD5";
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

    public static String hutoolMD5(String input) {
        MD5 md5 = SecureUtil.md5();
        return md5.digestHex(input);
    }
}
