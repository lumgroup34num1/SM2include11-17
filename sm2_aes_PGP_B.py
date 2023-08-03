import hashlib, math, sys, socket, config
from sm2_keyExchange_TCP_P2 import *
from SM2_ECG import *
from Prepare import *
from random import randint
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

if __name__ == '__main__':
    # 服务端主机IP地址和端口号
    HOST = socket.gethostname()
    PORT = 2234

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                                 # TCP连接、IPV4协议
    try:                                                                                  # 连接密钥协商对方
        s.connect((HOST, PORT))
        print("连接成功，开始执行密钥协商......")
    except Exception as e:
        print('连接失败')
        sys.exit()

    print("初始化密钥协商参数......")                                                        # 设置椭圆曲线参数
    config.set_default_config()
    parameters = config.get_parameters()
    point_G = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    h = config.get_h()
                                                                                          # 获取ID、公钥等公开信息
    IDA = 'ALICE123@YAHOO.COM'
    IDB = 'BOB456@YAHOO.COM'
    klen = 128                                                                            # 生成AES使用的128bit密钥
    key = key_pair_generation(parameters)                                                 # 生成公私钥对
    dB, PB = key[0], key[1]

    PA_x, PA_y = eval(s.recv(1024).decode())                                              # 向A发送固定公钥
    s.sendall(str([PB.x, PB.y]).encode())

    RA_x, RA_y = eval(s.recv(1024).decode())
    print(f"RA接收成功:({RA_x},{RA_y})")
    SB, RB, S2, KB = KeyExc_stepB1(IDA, IDB, dB, PB, Point(RA_x, RA_y), Point(PA_x, PA_y), klen, q, a, b, n, h,
                                   point_G)                                               # 密钥协商流程B1-B9步骤
    s.sendall(SB.encode())
    s.sendall(str([RB.x, RB.y]).encode())
    print(f"SB发送成功:{SB}")
    print(f"RB发送成功:({RB.x},{RB.y})")
    SA = s.recv(1024).decode()
    if (KeyExc_stepB2(S2, SA)):                                                           # 协商流程B10步骤
        print('密钥协商成功,临时会话密钥为:')
        s.sendall(str('1').encode())                                                      # 向P1发送确认信息
        print(f'KB:{(KB)}')
    else:
        print("密钥协商失败,S2!=SA")
        s.sendall(str('0').encode())

    print("密钥协商结束，开始通信......")
    key = binstr_to_bytes(KB)
    cipher = AES.new(key, AES.MODE_ECB)                                                   # 使用AES-ECB模式加密通信

    temp_key = s.recv(1024)
    temp_key = cipher.decrypt(temp_key)
    session_key = unpad(temp_key, AES.block_size).decode()
    print(f"解密临时会话密钥:{session_key}")


    key = binstr_to_bytes(session_key)                                                    #使用临时会话密钥通信
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = s.recv(1024)
    temp = cipher.decrypt(ciphertext)
    plaintext = unpad(temp, AES.block_size).decode()
    print(f"解密结果:{plaintext}")

    print("通信结束，断开连接......")
    s.close()
