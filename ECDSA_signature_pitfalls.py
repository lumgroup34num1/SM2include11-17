import math, config, random
from SM2_ECG import *
from Prepare import *


def ECDSA_keygen(n, point_G):
    d = random.randint(1, n - 1)
    P = ECG_k_point(d, point_G)
    return d, P


def ECDSA_sign(d, m, n, point_G, k):
    R = ECG_k_point(k, point_G)
    r = ele_to_int(R.x)
    e = hash_sha3_256(m)                                                                                    # ECDSA使用sha3_256算法，具体定义见头文件 Prepare.py
    s = ((config.inverse(k, n)) * (int(e, 2) + d * r)) % n
    return r, s


def ECDSA_verify(r, s, P, m, n, point_G):
    e = hash_sha3_256(m)
    e = int(e, 2)
    w = config.inverse(s, n)
    R_ = ECG_ele_add(ECG_k_point((w * e) % n, point_G), ECG_k_point((w * r) % n, P))
    r_ = ele_to_int(R_.x)
    if (r == r_):
        return True
    return False


if __name__ == "__main__":
    config.set_default_config()                                                                             # 初始化椭圆曲线参数
    point_G = Point(config.get_Gx(), config.get_Gy())
    n = config.get_n()

    m = 'hello world'
    d = 123123123
    print(f"用户私钥为d:{d}")

    # Leaking k leads to leaking of d
    k = 1
    r, s = ECDSA_sign(d, m, n, point_G, k)
    e = int(hash_sha3_256(m), 2)
    x = ((k * s - e) * config.inverse(r, n)) % n                                                             # x=(k*s-e)/r
    if (x == d): print(f"泄露k时，破解私钥为:{x},破解成功")

    # Reusing k leads to leaking of d
    m1 = '123123';
    m2 = '456456';
    k = 10086
    r1, s1 = ECDSA_sign(d, m1, n, point_G, k)
    r2, s2 = ECDSA_sign(d, m2, n, point_G, k)
    k = ((int(hash_sha3_256(m1), 2) - int(hash_sha3_256(m2), 2)) * config.inverse(s1 - s2, n)) % n          # k=(e1-e2)/(s1-s2)
    x = ((k * s1 - int(hash_sha3_256(m1), 2)) * config.inverse(r1, n)) % n                                  # x=(k*s-e)/r
    if (x == d): print(f"重复使用k时，破解私钥为:{x},破解成功")

    # Tow users's same k leaks d
    m1 = '123123';
    m2 = '456456'
    d1 = 123;
    d2 = 456;
    k = 10086
    r1, s1 = ECDSA_sign(d1, m1, n, point_G, k)
    r2, s2 = ECDSA_sign(d2, m2, n, point_G, k)

    x2 = ((k * s2 - int(hash_sha3_256(m2), 2)) * config.inverse(r2, n)) % n                                 # x2=(k*s2-e2)/r2
    x1 = ((k * s1 - int(hash_sha3_256(m1), 2)) * config.inverse(r1, n)) % n                                 # x1=(k*s1-e1)/r1
    print("用户1、2使用相同k时:")
    if (x2 == d2): print(f"用户1破解用户2私钥为{x2},破解成功")
    if (x1 == d1): print(f"用户2破解用户1私钥为{x1},破解成功")

    # forge sig if m is not checked
    # 见伪造中本聪签名project
