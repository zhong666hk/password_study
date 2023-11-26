# password_study
## 1.古典密码学
###  1.1替换法
* 1.单表替换
  * 规则: b-->w e-->c
    * 例如: bee-->wcc
* 2.多表替换
  * 规则1: b-->q,w-->r,e-->c
  * 规则2: b-->t,w-->y,e-->u
  * 规则3: b-->f,w-->g,e-->h
  这里就会多个规则表轮回 1个字符或几个字符就换张表
    * 例如: bee--->quh (1个字符就换一个)


### 1.2位移法
* 1.按照字母表位移
* 2.相关的密码名--(凯撒加密)--Caesar

### 1.3古典加密方式的破解
* 1.频率分析法---概率论
```text
根据在密文中的字符出现的次数，进行排序。然后带到密文中解密
```

```java
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
     * @throws
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
     * @throws 
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
```
**byte和bit的关系**
```text
在UTF-8编码格式下，一个中文对应3个字节
在GBK编码格式下，一个中文对应2个字节
英文没有编码格式影响，一个英文对应1个字节
```
```java
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
```

## 2.进代密码学  

**恩尼格玛密码机**
核心使用的也是移位法和替换法  
--人工智能之父--图灵破解  
## 3.现代密码学 
###  3.1散列函数
  * 散列函数也称 哈希函数
    * 常见的加密方式：MD5、SHA-1、SHA-256
      * MD5 可以将任意长度的原文生成一个128位(16字节)的哈希值
      * SHA-1 可以将任意长度的原文生成一个160位(20字节)的哈希值
        * SHA-1、SHA-256区别:
```text
SHA-1的哈希值长度为160位，而SHA-256的哈希值长度为256位。 因此，SHA-256提供了更高的安全性和更大的哈希空间，使其比SHA-1更难以被暴力破解
```

```java
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
```

```java
public class SHA_1Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 原文
        String input="aa";
        // 自带的MD5
        StringBuilder sb = originSHA1(input);
        System.out.println("originSHA1=\t"+sb);
        String hutoolSHA1 = hutoolSHA1(input);
        System.out.println("hutoolSHA1=\t"+hutoolSHA1);
    }
    private static StringBuilder originSHA1(String input) throws NoSuchAlgorithmException {
        // 算法
        String algorithm="SHA-1";
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

    public static String hutoolSHA1(String input) {
        Digester digester = SecureUtil.sha1();
        return digester.digestHex(input);
    }
}
```

```java
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
```

```java
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
```
### 3.2对称加密
  * 对称加密，使用的加密方式和解密方式，使用的是**同一把密钥**
    * 流加密和块加密：123456789
      * 流加密：字符一个一个的加密 1加密，再2加密....
      * 块加密：先分块再对块加密 1234成块加密，再5678加密，最后9XXX（XXX为补位数字）加密
        * 块加密相当于分组加密
  * 常见的加密方式 
    * DES: Data Encryption Standard 即数据加密标准--**des加密key必需为8位**
    * AES: Advanced Encryption Standard 高级加密标准
  * 特点
    * 加密速度快
    * 密文可逆，一旦密钥文件泄露，就会导致数据暴露
    * 加密后编码表找不到对应的字符，就会出现乱码---(编码表上没有负数)
    * 一般结合Base64使用
      * Base64介绍:
base64 不是加密算法，是可读性算法  
base64 目的不是保护数据，是为了可读性  
base64 是由A-Z,a-Z,0-9,+,/组成
**原理**
```text
    base64,是3个字节为一组，一个字节8位，一共就是24位，base64把三个字节
    转化成4组。每组6位，一个字节应该是八位。缺少两位。在高位进行0补齐。这样就会
    将值控制在0~63之间。
    
    在base64里面，需要设置一共3个字节，为一组。如果在输出的时候不够3个字节就需要 = 号进行补齐
```


```java
public class DES {
  public static void main(String[] args) throws Exception {
    // 定义原文
    String input ="钟";
    //定义key --->des加密key必需为8位
    String key ="12345678";
    // 定义加密算法 "DES/ECB/PKCS5Padding"
//        String transformation ="DES"; //p2aWhkJHd10= 不写加密模式默认是ECB和填充
    String transformation ="DES/ECB/PKCS5Padding"; //p2aWhkJHd10=
    // 加密类型
    String algorithm="DES";

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
```
```java
public class AES {
    public static void main(String[] args) throws Exception {
        // 定义原文
        String input ="钟";
        //定义key --->aes加密key必需为16位
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
```
* **AES和DES是基本一样的**
因为AES是高级加密，key是16位
  DES是标准加密，key是8位

* **加密模式**
String transformation ="AES/CBC/PKCS5Paddin";
Cipher cipher = Cipher.getInstance(transformation)

ECB:加密模式
CBC:加密模式 ：IV向量必需是8字节

* **填充模式**
PKCS5Paddin:填充
NoPadding：不填充 原文必需是8字节的整数倍


### 3.非对称加密
  * 非对称加密，使用的加密方式和解密方式，使用的是**两把密钥**  
    * 私钥加密必需公钥解密，公钥加密必需私钥解密，
  * 常见的算法
    *  RSA
    *  ECC  
  * 特点
    *  无需传输私钥，天然防窃听
    *  每人两把钥匙，不会随着人数的增加，导致密钥几何增加
    *  支持数字签名
  * 缺点
    * 加密速度慢
**RSA**
```java
public class RSA_test {
    private static PrivateKey privateKey;
    private static PublicKey publicKey ;

    public static void main(String[] args) throws Exception {
        // 原文
        String input = "钟";
        // 算法
        String algorithm="RSA";
        // 加密
        byte[] bytes = RSA_ENCRYPT(algorithm, input);
        System.out.println("加密后\t"+Base64.encode(bytes));
        // 解密
        byte[] bytes1 = RAS_DECRYPT(algorithm, bytes);
        System.out.println("加密后\t"+new String(bytes1));
    }

    /**
     * 解密
     * @param algorithm 算法
     * @param bytes 密文
     */
    private static byte[] RAS_DECRYPT(String algorithm, byte[] bytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return cipher.doFinal(bytes);
    }

    /**
     *  加密
     * @param algorithm 算法
     * @param input 原文
     */
    private static byte[] RSA_ENCRYPT(String algorithm, String input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 生成公钥和私钥
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        // 获取私钥、公钥的字节数组
        byte[] privateKeyEncoded = privateKey.getEncoded();
        byte[] publicKeyEncoded = publicKey.getEncoded();

        // 转码
        System.out.println(Base64.encode(privateKeyEncoded));
        System.out.println(Base64.encode(publicKeyEncoded));

        // 加密
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(input.getBytes());
        return bytes;
    }
}
```
封装后-->将公钥和私钥都写入文件中
```java
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
```
**ECC**





## 4.密码怎么设置才合适
  * 1.密码不要设置太常见
  * 2.各个应用不要设置一样，撞库。在别的软件设置的密码防范措施不行。导致密码泄露
  * 3.设置密码的时候，可以加一些特殊的标记。京东 jdXXX,zfbXXX


