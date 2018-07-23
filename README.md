## calico-precheck

部署calico之前检查网络环境是否符合要求。

编译二进制需要libpcap-dev库，Ubuntu安装：`sudo apt-get install libpcap-dev`
要求：有一台机器（跳板机）可以免密码ssh登录其他所有机器，并在其他机器上拥有免密码sudo权限。

用法：
1. 运行`make`，编译所需的二进制
2. 复制`tcp-send`,`ipip-send`和`capture-packets`到 ** 所有主机 ** 的`/tmp`目录下
3. 编写集群中主机列表（假设文件名为`hosts.list`），列明各主机的主机名、IP地址、网卡MAC地址、网卡名称、ssh登录用户名、ssh登录端口
4. 跳板机上运行`check-all -f <主机列表文件名>`，检查各主机间的网络是否满足需求。
主机列表格式：
<主机名> <ssh登录用户名> <主机IP> <ssh登录端口> <主机MAC> <主机网卡名称> 
