package com.wbu.Dome2_Byte;

public class Byte_Bit {
    public static void main(String[] args) {
        String text="a";
        String text2="钟";
        byte[] bytes = text.getBytes();
        for (byte aByte : bytes) {
            System.out.println(aByte);
            System.out.println(Integer.toBinaryString(aByte)); // 获取2进制
            System.out.println(Integer.toString(aByte));    //获取编码格式
        }
        System.out.println("===============================");
        byte[] text2Bytes = text2.getBytes();
        for (byte text2Byte : text2Bytes) {
            System.out.println(text2Byte);
            System.out.println(Integer.toBinaryString(text2Byte));
            System.out.println(Integer.toString(text2Byte));
            System.out.println("----------------");
        }
    }
}
