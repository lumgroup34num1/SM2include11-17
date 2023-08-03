
import hashlib,math,socket,sys,config
from random import randint
from SM2_ECG import *
from Prepare import *


S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
S.bind((socket.gethostname(),1234))
S.listen(5)
print(f'服务器启动成功,地址{socket.gethostname()},端口号:1234')

con,addr=S.accept()
print(f'地址{addr[0]},端口号{addr[1]}客户端接入......')
print("开始执行两方SM2签名......")


print("初始化签名参数......")
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())
n = config.get_n()
a = config.get_a()
b = config.get_b()

M='hello world'
IDA = 'ALICE123@YAHOO.COM'
IDB = 'BOB456@YAHOO.COM'

key = key_pair_generation(parameters)
d1 = key[0]
print("子私钥d1:",d1)
P1 = key[1]

d1_inv = config.inverse(d1, n)
P1=ECG_k_point(d1_inv,point_G)
print(f"发送P1:{P1}")
con.sendall(str([P1.x,P1.y]).encode())

x,y= eval(con.recv(1024).decode())

print('P接收完毕')
ZA=get_Z(IDA+IDB, Point(x,y))
M1=ZA+M
e = hash_function(M1)
e = bytes_to_int(bits_to_bytes(e))
k1=randint(1,n-1)
Q1 = ECG_k_point(k1, point_G)
con.sendall(str(e).encode())
print('e发送完毕')
con.sendall(str([Q1.x,Q1.y]).encode())
print('Q1发送完毕')
r= int(con.recv(1024).decode())
print('r接收完毕')
s2,s3= eval(con.recv(1024).decode())
print('s2,s3接收完毕')
s=((d1*k1)*s2+d1*s3-r)%n
if(s==0 or s==n-r):
    print("运算异常，s==0 or s==n-r")
    sys.exit()

con.sendall(str([r,s]).encode())
print("运算成功，签名为:")
print(f"r:{r}")
print(f"s:{s}")

print("运算结束，断开连接......")


S.close()
