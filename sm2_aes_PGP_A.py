import hashlib, math, sys, socket, config
from sm2_keyExchange_TCP_P1 import *
from SM2_ECG import *
from Prepare import *
from random import randint
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

if __name__ == '__main__':
    S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                       # TCP连接、IPV4协议
    S.bind((socket.gethostname(), 2234))
    S.listen(5)
    print(f'服务器启动成功,主机名{socket.gethostname()},端口号:2234')

    con, addr = S.accept()
    print(f'主机名{addr[0]},端口号{addr[1]}客户端接入......')
    print("开始执行密钥协商......")

    print("初始化密钥协商参数......")                                              # 设置椭圆曲线参数
    config.set_default_config()
    parameters = config.get_parameters()
    point_G = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    h = config.get_h()

    IDA = 'ALICE123@YAHOO.COM'                                                 # 获取ID、公钥等公开信息
    IDB = 'BOB456@YAHOO.COM'
    key = key_pair_generation(parameters)                                      # 生成公私钥对
    dA, PA = key[0], key[1]
    klen = 128                                                                 # 生成AES使用的128bit密钥

    con.sendall(str([PA.x, PA.y]).encode())                                    # 向B发送固定公钥
    PB_x, PB_y = eval(con.recv(1024).decode())

    rA, RA = KeyExc_stepA1(point_G, n)                                         # 密钥协商流程A1-A3步骤
    con.sendall(str([RA.x, RA.y]).encode())
    print(f"RA发送成功：({RA.x},{RA.y})")
    SB = con.recv(1024).decode()
    RB_x, RB_y = eval(con.recv(1024).decode())
    print(f"SB接收成功:{SB}")
    print(f"RB接收成功：({RB_x},{RB_y})")
    SA, KA = KeyExc_stepA2(IDA, IDB, rA, RA, Point(RB_x, RB_y), SB, dA, PA, Point(PB_x, PB_y), klen, q, a, b, n,
                           h)                                                  # 密钥协商流程A4-A10步骤
    con.sendall(SA.encode())
    print(f"SA发送成功:{SA}")
    if (int(con.recv(1024).decode())):                                         # 确认导出临时会话密钥是否有效
        print('密钥协商成功,临时会话密钥为:')
        print(f'KA:{(KA)}')
    else:
        print("密钥协商失败,S2!=SA")

    print("密钥协商结束，开始通信......")

    key = binstr_to_bytes(KA)
    cipher = AES.new(key, AES.MODE_ECB)                                        # 使用AES-ECB模式加密通信

    session_key = "00000000000000000000000000000000000000000010000100010110111111110000011111110110000111100101100111111010000110101100110011001100"
    C = cipher.encrypt(pad(session_key.encode(), AES.block_size))              #使用临时会话密钥通信
    con.sendall(C)
    print(f'发送加密会话密钥:{C}')

    M = "hello from Alice"
    key = binstr_to_bytes(session_key)
    cipher = AES.new(key, AES.MODE_ECB)
    C = cipher.encrypt(pad(M.encode(), AES.block_size))
    con.sendall(C)
    print(f'发送加密消息:{C}')

    print("通信结束，断开连接......")
    S.close()
