import math, config, random
from SM2_ECG import *
from Prepare import *


def Schnorr_sign_with_k(d, m, n, point_G, k):
    R = ECG_k_point(k, point_G)
    e = int(hash_sha3_256(str(R) + m), 2)
    s = (k + e * d) % n
    return R, s


def Schnorr_verify_with_e(e, R, s, P, n, point_G):
    sG = ECG_k_point(s, point_G)
    eP = ECG_k_point(e, P)
    res = ECG_ele_add(R, eP)
    if (res.x == sG.x and res.y == sG.y):
        return True
    return False


def ECDSA_sign_with_k(d, m, n, point_G, k):
    R = ECG_k_point(k, point_G)
    r = ele_to_int(R.x)
    e = hash_sha3_256(m)                                                                        # ECDSA使用sha3_256算法，具体定义见头文件 Prepare.py
    s = ((config.inverse(k, n)) * (int(e, 2) + d * r)) % n
    return r, s


if __name__ == '__main__':
    config.set_default_config()                                                                 # 初始化椭圆曲线参数
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()

    m = 'hello world'
    d = 10086
    P = ECG_k_point(d, point_G)

    #A. Leaking k leads to leaking of d
    k = 1
    R, s = Schnorr_sign_with_k(d, m, n, point_G, k)                                             # 指定k的Schnorr签名
    e = int(hash_sha3_256(str(R) + m), 2)
    x = ((s - k) * config.inverse(e, n)) % n
    if (x == d): print(f"泄露k时，破解私钥为:{x},破解正确")                                          # x=(s-k)/e

    #B. Reusing k leads to leaking of d
    m1 = '123123';m2 = '456456'
    k = 10086
    R1, s1 = Schnorr_sign_with_k(d, m1, n, point_G, k)
    R2, s2 = Schnorr_sign_with_k(d, m2, n, point_G, k)
                                                                                               # k=(s1-s2)/(e1-e2)
    x = ((s1 - s2) * config.inverse(int(hash_sha3_256(str(R1) + m1), 2) - int(hash_sha3_256(str(R2) + m2), 2), n)) % n
    if (x == d): print(f"重复使用k时，破解私钥为:{x},破解正确")

    #C. Tow users's same k leaks d
    m1 = '123123';m2 = '456456'
    d1 = 123;d2 = 456;
    k = 10086
    R1, s1 = Schnorr_sign_with_k(d1, m1, n, point_G, k)
    R2, s2 = Schnorr_sign_with_k(d2, m2, n, point_G, k)

    x2 = ((s2 - k) * config.inverse(int(hash_sha3_256(str(R2) + m2), 2), n)) % n                # 相当于知道了对方的k
    x1 = ((s1 - k) * config.inverse(int(hash_sha3_256(str(R1) + m1), 2), n)) % n
    print("用户1、2使用相同k时:")
    if (x2 == d2): print(f"\t用户1破解用户2私钥为{x2},破解正确")
    if (x1 == d1): print(f"\t用户2破解用户1私钥为{x1},破解正确")

    #D. forge signature if only H(m) is checked
    R, s = Schnorr_sign_with_k(d, m, n, point_G, k)                                             # 已有签名
    e = int(hash_sha3_256(str(R) + m), 2)
                                                                                                # 伪造签名 s'=2*s  R'=2k*G  e'=2*e
    s1 = (2 * s) % n
    R1 = ECG_k_point(2 * k, point_G)
    e1 = (2 * e) % n

    if (Schnorr_verify_with_e(e1, R1, s1, P, n, point_G)):                                      # 验证伪造签名 s'G=2sG=2kG+2edG=2R+2eP=R'+e'P
        print(f"只检查H(m')时，伪造签名为\n\tH(m'):{e1}\n\tR':{R1}\n\ts':{s1}")

    #E. same d and k with ECDSA lead to leaking of d
    m1 = '123123';m2 = '456456'
    d = 123123;k = 10086
    R1, s1 = Schnorr_sign_with_k(d, m1, n, point_G, k)                                          # 指定k的Schnorr签名
    r2, s2 = ECDSA_sign_with_k(d, m2, n, point_G, k)                                            # 指定k的ECDSA签名
    e1 = int(hash_sha3_256(str(R1) + m1), 2)
    e2 = int(hash_sha3_256(m2), 2)

    temp1 = (s1 * s2 - e2) % n
    temp2 = (e1 * s2 + r2) % n
    x = (temp1 * config.inverse(temp2, n)) % n                                                  # d=(s1*s2-e2)/(e1*s2+r2)
    if (x == d):
        print(f"与ECDSA使用相同d、k时，破解私钥为{x},破解正确")
