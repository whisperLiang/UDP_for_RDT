# “高级计算机网络”课程实验相关工具集

## chunk_generator.py

* 作用：

    产生一个自定义大小的文件

* 参数：

```
-s, --size ：指定文件大小，单位为G，默认大小为2G
-o, --output ：指定文件的输出位置，默认为output.bin
-c, --char ：指定文件的填充字符（在generate_same_char模式下起作用）
generate_type ：指定文件产生模式，共两种模式，generate_same_char（产生一个全部都是某字节的文件），generate_random_char（产生一个包含随机字符串的文件）
```

* 示例用法：

以下命令将产生一个大小为0.5G的包含随机字符的文件

```
python3 chunk_generator.py generate_random_char -s 0.5
```

## GetScore.py

* 作用：用户自测在server端和client端传送文件，记录传送文件的时间、计算文件的md5、评分

* 实现步骤：

  * server端和client端需要安装openssh-server，GetScore通过ssh连接server端和client端来实现命令控制和文件传输。

  * GetScore首先将同学的server.py和chunk_generator.py放置到server服务器上，将client.py放置到client服务器上，然后运行chunk_generator.py产生一个文件（固定名字为output.bin），然后先运行server.py启动监听端口，然后运行client.py接收文件，接收完毕之后，运行md5sum分别计算两端文件的md5并记录，删除sever和client的文件，然后记录总运行时间，将结果保存在result.txt文件当中。

* 要求：
  * chunk_generator.py和GetScore.py需放置在同一文件夹内。
  * 用户编写的server和client端的文件传输代码分别命名为server.py和client.py。
  * 测试代码默认以server发送消息，client接收消息，编写server.py和client.py时需相应注意。
  * 自测时代码的放置位置可自定义，但上传代码必须按下述文本结构放置。
  

* 参数：（这几个参数主要用来利用ssh登陆和控制client、server服务器，上传文件等）

```
--client_ip ：client服务器ip
--client_password：client服务器密码
--client_username：client服务器用户名
--server_ip：server服务器ip
--server_port： sever服务器开启的监听端口
--server_password：server服务器密码
--server_username：server服务器用户名
--client_file：client.py文件位置
--server_file：server.py文件位置 
--generate_type：chunk_generator的文件产生模式
--size：指定chunk_generator生成文件的大小
```

* 示例：

```
python3 ./GetScore.py --client_ip 192.168.43.131 --client_password 123456 --client_username jhon --server_ip 192.168.43.130 --server_port 49999 --server_password 123456 --server_username jhon --client_file ./work/22020124/client.py --server_file ./work/22020124/server.py --generate_type generate_random_char --size 1
```

* 最后结果：  

```
+------------+-------------------------------------+-------------------------------------+---------+
|  耗时(s)   |           server端文件md5           |           client端文件md5           | md5检测 |
+------------+-------------------------------------+-------------------------------------+---------+
| 20.2272228 | b'13b3342447b97ea161b2fc74aea6fd96' | b'13b3342447b97ea161b2fc74aea6fd96' |   True  |
+------------+-------------------------------------+-------------------------------------+---------+
```

## GetAllScore.py

* 作用：批量测试在server端和client端传送文件，记录传送文件的时间、计算文件的md5、评分（提交作业后评测用，用户无需处理）

## 用户自测流程
用户自测时，将GetScore.py和chunk_generator.py放在一个文件夹中，开启server和client对应的虚拟机，运行GetScore.py即可。

## 提交作业流程

用户提交作业时，将client.py和server.py放在同一文件夹中（以学号为命名）。 

目录如下：  

```
├── 22020124  学生写的文件放在这里，client必须命名为client.py，server必须命名为server.py
   ├── client.py
   └── server.py

```

最终测试时目录如下：
``` 
├─work
    │─result.csv
    │
    ├─22020024 学生写的文件放在这里，client必须命名为client.py，server必须命名为server.py
    │      client.py
    │      server.py
    │
    └─22020124
            client.py
            server.py

```
## 要求

1. 自测时GetScore、client、server所在的服务器必须连通
2. 自测时client、server安装openssh-server，GetScore安装openssh-client
3. 各组提交的作业命名固定为client.py，server.py，放在学号命名的文件夹中
