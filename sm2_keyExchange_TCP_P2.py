import hashlib, math, sys, socket, config
from random import randint
from SM2_ECG import *
from Prepare import *

def KeyExc_stepB1(IDA, IDB, dB, PB, RA, PA, klen, q, a, b, n, h ,point_G):                     # 协商流程B1-B9步骤
    w = math.ceil(math.ceil(math.log(n, 2)) / 2) - 1
    ZA = get_Z(IDA, Point(PA.x, PA.y))
    ZB = get_Z(IDB, Point(PB.x, PB.y))
    rB = randint(1, n - 1)
    RB = ECG_k_point(rB, point_G)
    x2, y2 = ele_to_int(RB.x), ele_to_int(RB.y)
    x2_ = 2 ** w + (x2 & (2 ** w - 1))
    tB = (dB + x2_ * rB) % n
    x1, y1 = ele_to_int(RA.x), ele_to_int(RA.y)
    if (x1 ** 3 + a * x1 + b) % q != (y1 ** 2) % q:
        print("协商失败，RA不满足椭圆曲线方程")
        return False
    x1_ = 2 ** w + (x1 & (2 ** w - 1))
    V = ECG_k_point(h * tB, ECG_ele_add(Point(PA.x, PA.y), ECG_k_point(x1_, Point(RA.x, RA.y))))
    if V.x == ECG_ele_zero().x and V.y == ECG_ele_zero().y:
        print("协商失败，V是无穷远点")
        return False
    xV = bytes_to_bits(ele_to_bytes(V.x)).replace('0b', '')
    yV = bytes_to_bits(ele_to_bytes(V.y)).replace('0b', '')
    KB = KDF(xV + yV + ZA + ZB, klen)                                              # 导出临时会话密钥
    x1 = bytes_to_bits(ele_to_bytes(x1)).replace('0b', '')
    y1 = bytes_to_bits(ele_to_bytes(y1)).replace('0b', '')
    x2 = bytes_to_bits(ele_to_bytes(x2)).replace('0b', '')
    y2 = bytes_to_bits(ele_to_bytes(y2)).replace('0b', '')
    temp = hash_function(xV + ZA + ZB + x1 + y1 + x2 + y2).replace('0b', '')
    SB = hash_function('00000010' + yV + temp).replace('0b', '')
    S2 = hash_function('00000011' + yV + temp).replace('0b', '')
    return SB, RB, S2 ,KB

def KeyExc_stepB2(S2,SA):                                                          # 协商流程B10步骤
        return (S2==SA)

if __name__=='__main__':
    # 服务端主机IP地址和端口号
    HOST = socket.gethostname()
    PORT = 2234

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                          # TCP连接、IPV4协议
    try:                                                                           # 连接密钥协商对方
        s.connect((HOST, PORT))
        print("连接成功，开始执行密钥协商......")
    except Exception as e:
        print('连接失败')
        sys.exit()

    print("初始化密钥协商参数......")                                                  # 设置椭圆曲线参数
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
    klen = 100
    key = key_pair_generation(parameters)                                           # 生成公私钥对
    dB, PB= key[0],key[1]

    PA_x, PA_y = eval(s.recv(1024).decode())                                        # 向A发送固定公钥
    s.sendall(str([PB.x, PB.y]).encode())

    RA_x, RA_y = eval(s.recv(1024).decode())
    print(f"RA接收成功:({RA_x},{RA_y})")
    SB,RB,S2,KB=KeyExc_stepB1(IDA, IDB, dB, PB, Point(RA_x, RA_y), Point(PA_x, PA_y), klen, q, a, b, n, h, point_G)  # 协商流程B1-B9步骤
    s.sendall(SB.encode())
    s.sendall(str([RB.x, RB.y]).encode())
    print(f"SB发送成功:{SB}")
    print(f"RB发送成功:({RB.x},{RB.y})")
    SA = s.recv(1024).decode()
    if(KeyExc_stepB2(S2,SA)):                                                       # 协商流程B10步骤
        print('密钥协商成功,临时会话密钥为:')
        s.sendall(str('1').encode())                                                # 向P1发送确认信息
        print(f'KB:{(KB)}')
    else:
        print("密钥协商失败,S2!=SA")
        s.sendall(str('0').encode())
    print("密钥协商结束,关闭连接......")
    s.close()




