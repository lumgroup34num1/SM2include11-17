import hashlib,math,sys,socket,config
from random import randint
from SM2_ECG import *
from Prepare import *

def KeyExc_stepA1(point_G,n):                                                   #协商流程A1-A3步骤
    rA=randint(1,n)
    RA=ECG_k_point(rA,point_G)
    return rA,RA

def KeyExc_stepA2(IDA, IDB, rA, RA, RB, SB, dA, PA, PB, klen,q,a,b,n,h):            #协商流程A4-A10步骤
    ZA = get_Z(IDA, Point(PA.x, PA.y))
    ZB = get_Z(IDB, Point(PB.x, PB.y))
    w = math.ceil(math.ceil(math.log(n, 2)) / 2) - 1
    x1, y1 = ele_to_int(RA.x), ele_to_int(RA.y)
    x1_ = 2 ** w + (x1 & (2 ** w - 1))
    tA = (dA + x1_ * rA) % n
    x2, y2 = ele_to_int(RB.x), ele_to_int(RB.y)
    if (y2 ** 2) % q != (x2 ** 3 + a * x2 + b) % q:
        print("协商失败，RB不满足椭圆曲线方程")
        return False
    x2_ = 2 ** w + (x2 & (2 ** w - 1))
    U = ECG_k_point(h * tA, ECG_ele_add(Point(PB.x, PB.y), ECG_k_point(x2_, Point(RB.x, RB.y))))
    if U.x == ECG_ele_zero().x and U.y == ECG_ele_zero().y:
        print("协商失败，U是无穷远点")
        return False
    xU = bytes_to_bits(ele_to_bytes(U.x)).replace('0b', '')
    yU = bytes_to_bits(ele_to_bytes(U.y)).replace('0b', '')
    KA = KDF(xU + yU + ZA + ZB, klen)                                           # 导出临时会话密钥
    x1 = bytes_to_bits(ele_to_bytes(x1)).replace('0b', '')
    y1 = bytes_to_bits(ele_to_bytes(y1)).replace('0b', '')
    x2 = bytes_to_bits(ele_to_bytes(x2)).replace('0b', '')
    y2 = bytes_to_bits(ele_to_bytes(y2)).replace('0b', '')
    temp = hash_function(xU + ZA + ZB + x1 + y1 + x2 + y2).replace('0b', '')
    SB = hash_function('00000010' + yU + temp).replace('0b', '')
    SA = hash_function('00000011' + yU + temp).replace('0b', '')
    return SA,KA



if __name__ =='__main__':
    S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                       # TCP连接、IPV4协议
    S.bind((socket.gethostname(), 2234))
    S.listen(5)
    print(f'服务器启动成功,主机名{socket.gethostname()},端口号:2234')

    con, addr = S.accept()
    print(f'主机名{addr[0]},端口号{addr[1]}客户端接入......')
    print("开始执行密钥协商......")

    print("初始化密钥协商参数......")                                                # 设置椭圆曲线参数
    config.set_default_config()
    parameters = config.get_parameters()
    point_G = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    h = config.get_h()

    IDA = 'ALICE123@YAHOO.COM'                                                  # 获取ID、公钥等公开信息
    IDB = 'BOB456@YAHOO.COM'
    key = key_pair_generation(parameters)                                       # 生成公私钥对
    dA, PA = key[0], key[1]
    klen = 100


    con.sendall(str([PA.x, PA.y]).encode())                                     # 向B发送固定公钥
    PB_x, PB_y = eval(con.recv(1024).decode())

    rA,RA=KeyExc_stepA1(point_G,n)                                              # 协商流程A1-A3步骤
    con.sendall(str([RA.x, RA.y]).encode())
    print(f"RA发送成功：({RA.x},{RA.y})")
    SB = con.recv(1024).decode()
    RB_x, RB_y = eval(con.recv(1024).decode())
    print(f"SB接收成功:{SB}")
    print(f"RB接收成功：({RB_x},{RB_y})")
    SA,KA=KeyExc_stepA2(IDA, IDB, rA, RA, Point(RB_x, RB_y), SB, dA, PA, Point(PB_x, PB_y), klen,q,a,b,n,h) # 协商流程A4-A10步骤
    con.sendall(SA.encode())
    print(f"SA发送成功:{SA}")
    if (int(con.recv(1024).decode())):                                          # 确认导出临时会话密钥是否有效
        print('密钥协商成功,临时会话密钥为:')
        print(f'KA:{(KA)}')
    else:
        print("密钥协商失败,S2!=SA")
    print("密钥协商结束,关闭连接......")
    S.close()