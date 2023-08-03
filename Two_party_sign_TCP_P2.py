
import hashlib,math,socket,sys,config
from random import randint
from SM2_ECG import *
from Prepare import *


# 服务端主机IP地址和端口号
HOST = socket.gethostname()
PORT = 1234

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # 连接服务器
    s.connect((HOST, PORT))
    print("连接成功，开始执行两方SM2签名......")
except Exception as e:
    print('连接失败')


print("初始化签名参数......")
config.set_default_config()
parameters = config.get_parameters()
point_G = Point(config.get_Gx(), config.get_Gy())
n = config.get_n()
a = config.get_a()
b = config.get_b()
q = config.get_q()

key = key_pair_generation(parameters)
d2 = key[0]
print("子私钥d2:",d2)
P2 = key[1]
d2_inv = config.inverse(d2, n)
x,y= eval(s.recv(1024).decode())

P1=Point(int(x),int(y))
P=ECG_k_point(d2_inv,P1)
temp=ECG_k_point(q-1,point_G)
P=ECG_ele_add(P,temp)
print(f"公钥P:\n{P}")
s.sendall(str([P.x,P.y]).encode())

print('P发送完毕')
e= int(s.recv(1024).decode())
print('e接收完毕')
x,y= eval(s.recv(1024).decode())
print('Q1.y接收完毕')
Q1=Point(x,y)
k2,k3=randint(1,n-1),randint(1,n-1)
Q2 = ECG_k_point(k2, point_G)
X=ECG_ele_add(ECG_k_point(k3,Q1),Q2)
x1,y1=X.x,X.y
r=(x1+e)%n
if(r==0):
    print("运算异常，r=0 mod n")
    sys.exit()
s2=(d2*k3)%n
s3=(d2*(r+k2))%n
s.sendall(str(r).encode())
print('r发送完毕')
s.sendall(str([s2,s3]).encode())
print('s2,s3发送完毕')
rand,sig= eval(s.recv(1024).decode())
print("运算成功，签名为")
print(f"r:{rand}")
print(f"s:{sig}")
print("运算结束，断开连接......")


# 关闭连接
s.close()
