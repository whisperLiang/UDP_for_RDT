# 高级计算机网络大作业
## 在代码基础上增加了两种多线程压缩算法
源码：https://github.com/ZiYang-xie/UDP_RDT
## 压缩算法
多线程 lzma 算法使用文件对象的 read 方法以大小为 chunk_size 的块读取输入文件。然后它为每个块创建一个新线程以使用 com-press_chunk 函数压缩块。

zstd 算法使用 zstd 模块中的 ZstdCompressor类来压缩输入文件并将压缩数据写入输出文件ZstdCompressor 类的级别参数决定了压缩级别，级别越高，压缩效果越好，但压缩时间越长。
