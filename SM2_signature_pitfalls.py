import hashlib, config, math
from SM2_ECG import *
from Prepare import *


def sm2_sign_with_k(M, IDA, dA, PA, point_G, k):
    ZA = get_Z(IDA, PA)
    M1 = ZA + M
    e = hash_function(M1)
    e = bytes_to_int(bits_to_bytes(e))
    X = ECG_k_point(k, point_G)
    x1 = bytes_to_int(ele_to_bytes(X.x))
    r = (e + x1) % n
    if (r == 0 or r + k == n):                                                   # 由于是指定k，因此不满足条件直接退出
        return None
    s = (config.inverse(1 + dA, n) * (k - r * dA)) % n
    if (s == 0):
        return None
    return (r, s)


def ECDSA_sign_with_k(d, m, n, point_G, k):
    R = ECG_k_point(k, point_G)
    r = ele_to_int(R.x)
    e = hash_sha3_256(m)                                                        # ECDSA使用sha3_256算法，具体定义见头文件 Prepare.py
    s = ((config.inverse(k, n)) * (int(e, 2) + d * r)) % n
    return r, s


if __name__ == '__main__':

    config.set_default_config()
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()

    d = 10086
    P = ECG_k_point(d, point_G)
    IDA = 'ALICE123@YAHOO.COM'
    M = "hello world"

    # A. Leaking k leads to leaking of d
    k = 1
    r, s = sm2_sign_with_k(M, IDA, d, P, point_G, k)                            # 指定k的SM2的签名
    x = ((k - s) * config.inverse(s + r, n)) % n                                # d=(k-s)/(r+s)
    if (x == d): print(f"泄露k时，破解私钥为:{x},破解正确")

    # B. Reusing k leads to leaking of d
    M1 = '123123';M2 = '456456'
    ID1 = 'ALICE123@YAHOO.COM'
    ID2 = 'BOB456@YAHOO.COM'
    k = 10086

    r1, s1 = sm2_sign_with_k(M1, ID1, d, P, point_G, k)
    r2, s2 = sm2_sign_with_k(M2, ID2, d, P, point_G, k)

    temp1 = (s2 - s1) % n
    temp2 = (s1 - s2 + r1 - r2) % n
    x = (temp1 * config.inverse(temp2, n)) % n                                  # d=(s2-s1)/(s1-s2+r1-r2)
    if (x == d): print(f"重复使用k时，破解私钥为:{x},破解正确")

    # C. Tow users's same k leaks d
    m1 = '123123';m2 = '456456'
    ID1 = 'ALICE123@YAHOO.COM'
    ID2 = 'BOB456@YAHOO.COM'
    d1 = 123123;d2 = 456456
    k = 10086

    r1, s1 = sm2_sign_with_k(m1, ID1, d1, P, point_G, k)
    r2, s2 = sm2_sign_with_k(m2, ID2, d2, P, point_G, k)

    x2 = ((k - s2) * config.inverse(s2 + r2, n)) % n                            # d2=(k-s2)/(s2+r2)
    x1 = ((k - s1) * config.inverse(s1 + r1, n)) % n                            # d1=(k-s1)/(s1+r1)
    print("用户1、2使用相同k时:")
    if (x2 == d2): print(f"\t用户1破解用户2私钥为{x2},破解正确")
    if (x1 == d1): print(f"\t用户2破解用户1私钥为{x1},破解正确")

    # D. same d and k with ECDSA lead to leaking of d
    m1 = '123123';d = 123123;k = 10086
    r1, s1 = ECDSA_sign_with_k(d, m1, n, point_G, k)                            # 指定k的ECDSA签名
    r2, s2 = sm2_sign_with_k(M, IDA, d, P, point_G, k)                          # 指定k的SM2的签名
    e1 = int(hash_sha3_256(m1), 2)

    temp1 = (s1 * s2 - e1) % n
    temp2 = (r1 - s1 * s2 - s1 * r2) % n
    x = (temp1 * config.inverse(temp2, n)) % n                                  # d=(s1s2-e1)/(r1-s1s2-s1r2)
    if (x == d): print(f"与ECDSA使用相同d、k时，破解私钥为{x},破解正确")
