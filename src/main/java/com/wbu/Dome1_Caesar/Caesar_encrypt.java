package com.wbu.Dome1_Caesar;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

public class Caesar_encrypt {
    public static void main(String[] args) throws IOException {
        String path="article.txt";
        StringBuilder article = readArticle(path);
        // 定义原文
        String input= String.valueOf(article);
        // 原文字符数
        ArrayList articleList = countChar(input);
        // 定义密钥
        int key=3;
        
        // 将字符移位-->凯撒加密
        String caesar = caesar(input, key);

        //解密
        String decryptCaesar = decryptCaesar(caesar, key);

        // 密文统计
        ArrayList decryptList = countChar(caesar);

        // 破解密钥-->猜想key
        int key2 = decryptCaesar_byProbability(articleList, decryptList);

        //破解--->概率论--图灵
        decrypt(caesar,key2);

    }

    /**
     * 根据密文和原文-->（频率）推断到key
     * @param articleList 原文频率
     * @param decryptList  密文频率
     * @return
     */
    private static int decryptCaesar_byProbability(ArrayList<Count> articleList, ArrayList<Count> decryptList) {
        // 猜测
        int key= decryptList.get(0).getC() - articleList.get(0).getC();
        System.out.println("猜测key="+key);
        return key;
    }

    /**
     * 原文和密文-->推算到key(频率统计)-->解密
     * @param caesar
     * @param key
     * @throws IOException
     */
    public static void decrypt(String caesar,int key) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("article_en.txt");
        try {
            // 解密
            char[] charArray=caesar.toCharArray();
            for (int i = 0; i < charArray.length; i++) {
                charArray[i]= (char) (charArray[i]-key);
            }
            fileOutputStream.write(new String(charArray).getBytes(StandardCharsets.UTF_8));
        }finally {
            fileOutputStream.close();
        }
    }

    /**
     *  知道key和密文解密
     * @param caesar 密文
     * @param key key
     * @return
     */
    private static String decryptCaesar(String caesar, int key) {
        StringBuilder newString = new StringBuilder();
        for (char c : caesar.toCharArray()) {
            newString.append((char) (c-key)); // 必需转为char
        }
        System.out.println("解密后的原文是："+newString);
        return newString.toString();
    }

    /**
     * 根据输入的字符串-->凯撒加密
     * @param input 要加密的字符串
     * @param key   加密的key-->位移法
     * @return
     */
    private static String caesar(String input,int key) {
        StringBuilder newString = new StringBuilder();
        for (char c : input.toCharArray()) {
            newString.append((char) (c+key)); // 必需转为char
        }
        System.out.println("凯撒加密后的密文是："+newString);
        return newString.toString();
    }

    /**
     * 读取文章
     * @param path 文章路径
     * @return
     * @throws IOException
     */
    private static StringBuilder readArticle(String path) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        try {
            byte[] bytes = new byte[1024];
            int len;
            StringBuilder stringBuilder = new StringBuilder();
            while ((len=fileInputStream.read(bytes))!= -1){
                stringBuilder.append(new String(bytes,0,len));
            }
            return stringBuilder;
        }
        finally {
            fileInputStream.close();
        }
    }

    /**
     * 字符统计次数
     * @param article  要统计的字符
     * @return
     */
    public static ArrayList countChar(String article){
        HashMap<Character, Integer> map = new HashMap<>();
        for (char c : article.toCharArray()) {
            if (map.containsKey(c)){
                map.put(c,map.get(c)+1);
            }else {
                map.put(c,1);
            }
        }
        ArrayList<Count> counts = new ArrayList<>();
        map.forEach((key,value)->{
            counts.add(new Count(key,value));
        });
        counts.sort((a,b)-> b.getCount()- a.getCount());
        counts.forEach(count -> {
            System.out.println("字符"+count.getC()+"出现的次数为\t"+count.getCount());
        });
        return counts;
    }
}
