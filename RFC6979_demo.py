
from Prepare import *


# 根据ECDSA参数，设置hash、hmac、q的长度为256bit
# hmac的hash算法采用sha256，具体定义见头文件 Prepare.py
def demo_RFC6979(key, m, q):
    h1 = hash_sha3_256(m)                                       #h1 = H(m)
    V = '0000001' * 32                                          #V = 0x01 0x01 0x01 ... 0x01
    K = '0' * 256                                               #K = 0x00 0x00 0x00 ... 0x00
    padkey = padzeore_to_len(bin(key).replace('0b', ''), 256)
    K = HMAC_K(K, V + '00000000' + padkey + h1)                 #K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    V = HMAC_K(K, V)                                            #V = HMAC_K(V)
    K = HMAC_K(K, V + '00000001' + padkey + h1)                 #K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    V = HMAC_K(K, V)
    while (True):
        T = ''
        while (len(T) < 256):
            V = HMAC_K(K, V)
            T = T + V
        k = int(T, 2)
        if (k > 0 and k < q):                                   #k∈[1,q-1]则成功，是否满足r!=0和r+s!=n在签名算法中判断
            break
        K = HMAC_K(K, V + '00000000')                           #K = HMAC_K(V || 0x00)，重新生成T
        V = HMAC_K(K, V)
    return k


if __name__ == '__main__':
    config.set_default_config()
    q = config.get_q()
    n = config.get_n()

    key = randint(1, n - 1)
    m = 'hello world'

    k = demo_RFC6979(key, m, q)
    if (k > 0 and k < q):
        print(f"随机数生成完成\nk:{k}")
