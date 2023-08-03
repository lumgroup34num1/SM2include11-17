# project11 impl sm2 with RFC6979
## 1、实验原理
  ECDSA是ECC与DSA的结合，整个签名过程与DSA类似，所不一样的是签名中采取的算法为ECC，最后签名出来的值也是分为r,s。
签名过程如下：
1、选择一条椭圆曲线Ep(a,b)，和基点G；

2、选择私有密钥k（k<n，n为G的阶），利用基点G计算公开密钥K=kG；

3、产生一个随机整数r（r<n），计算点R=rG；

4、将原数据和点R的坐标值x,y作为参数，计算SHA1做为hash，即Hash=SHA1(原数据,x,y)；

5、计算s≡r - Hash * k (mod n)

6、r和s做为签名值，如果r和s其中一个为0，重新从第3步开始执行

验证过程如下：

1、接受方在收到消息(m)和签名值(r,s)后，进行以下运算

2、计算：sG+H(m)P=(x1,y1), r1≡ x1 mod p。

3、验证等式：r1 ≡ r mod p。

4、如果等式成立，接受签名，否则签名无效。
## 2、运行结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/552d778b-2ec4-42fd-a013-229a09e4de1b)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/6aeca06a-c309-458d-9211-1cc62c303965)
# project 12 verify the above pitfalls with proof-of-concept code



# project 14 Implement a PGP scheme with SM2
## 1、实验原理
两方PGP通信采用TCP通信模拟真实网络通信过程，使用sm2密钥协商算法协商对称密钥，再使用AES加密以协商得到的密钥加密临时会话密钥，并使用AES加密以临时会话密钥加密通信消息。
## 2、实验结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/8733a5d6-441a-4ecb-adf7-0a1ff76442e8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/b0589df7-5362-4644-86ce-4e9ec09ed7e8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/63208b8e-95f8-4244-93d5-9836c0ae7ae5)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/8a7c4958-5243-4aa1-b84b-cb172498c8a7)
# project 15 implement sm2 2P sign with real network communication
## 1、实验原理
![sig.png](https://s2.loli.net/2022/07/28/quDUW4d1tXr2ayM.png)
<p align="center">两方SM2签名原理</p>

## 2、实验结果
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/4e09d4ae-a030-43d5-8634-4541938b0bc8)
![image](https://github.com/lumgroup34num1/SM2include11-17/assets/129478488/cc8d31a8-5755-4e0d-b6c6-da12c4543367)



# project 16 implement sm2 2P decrypt with real network communication

