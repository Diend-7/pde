# map_pde

## 简介

该工具包主要用于获取map系统采集到的次声、电磁和地震数据，还可以用于获取某些特定的fdsn站点波形数据。此外该工具包还可以获取map系统里面的站点信息以及map系统里面所检测到的事件信息。

- map站点介绍

目前map系统有4个站点，1号站点烟台，2号站点延边，3号站点白城，4号站点北京。

次声数据编号为1，地震数据编号为2，电磁数据编号为3（电磁数据较少，几乎没有）。

1号站点有3个次声设备对应编号（1, 2, 3)

2号站点有3个次声设备对应编号（1, 2, 3)

3号站点有3个次声设备、1个地震设备和1个电磁设备，分别对应编号（1, 2, 3   1    1)

4号站点有4个次声设备和1个地震设备，分别对应编号（1, 2, 3, 4   1)

- fdsn站点介绍

目前map系统接入的fdsn站点包括:

IM.I58H1..BDF,IM.I58H2..BDF,IM.I58H3..BDF,IM.I58H4..BDF

IM.I57H1..BDF,IM.I57H2..BDF,IM.I57H3..BDF

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2196c116-4c52-4306-b78a-3fcde0049db4/Untitled.png)

> 地图链接地址：[https://www.ctbto.org/map/](https://www.ctbto.org/map/)
> 

由于系统部署原因，请尝试获取**2023年3月之后的map数据和2023年4月10号之后的obspy数据**。

## 安装

```bash
pip install map_pde
```

## 快速开始

### 获取token

去map_pde的网站注册获取token已用来获取数据，官网地址：http://10.99.12.109:38090

登入之后去个人页面便可以获取自己的token

### 初始化客户端

```bash
from map_pde.client import Client

# 第一次使用的时候需要填入token,**之后使用的时候便可以不加入token了**
client = Client(sa_token="自己的token")
```

主要参数

- `base_url` - 默认为：“MAP”,目前只支持MAP。
- `satoken` - 访问数据所需要的token**,只有在第一次使用的时候需要填入，后续使用则不需要填入了，token过期之后需要再次填入。**

### 获取map系统采集的波形数据

```bash
from obspy import UTCDateTime

# 获取map系统波形数据
st = client.get_map_waveforms([1], [1], [1, 2], startTime=UTCDateTime("2023-03-07 12:00:01"), endTime=UTCDateTime("2023-03-07 12:01:00"))
print(st)

# 将获取到的map波形数据以图片的形式展现出来
for trace in st:
    trace.plot()

# 将获取到的波形数据保存到本地
client.get_map_waveforms([1], [1], [1, 2], startTime=UTCDateTime("2023-03-07 12:00:01"), endTime=UTCDateTime("2023-03-07 12:01:00"), filename="test.mseed")
```

- `site` - 不能为空，列表形式，因为只有四个站点，最多就是[1,2,3,4]。
- `dataType` - 获取的数据类型，默认为全部获取，包括次声、电磁和地震，列表形式，因为只有三种数据类型，最多就是[1,2,3]
- `device` - 设备编号，默认为全部获取，列表形式，目前1个站点最多只有4个设备，所有最多就是[1,2,3,4]
- `startTime` - 获取数据的开始时间，**目前最多可以获取连续的5小时数据**，如果想要获取更长的连续数据，请分多次请求获取。
- `endTime` - 获取数据的结束时间。
- `filename` - 将获取的数据保存的文件名，**如果设置了 filename则不会有返回值。**

### 获取某些fdsn的站点数据

```bash
st1 = client.get_obspy_waveforms(network="IM", station="I57*", channel="BDF", startTime="2023-04-08 12:00:00", endTime="2023-04-08 12:00:01")
```

- `network` - 网络，目前采集的只有IM的数据。
- `station` - 站点，目前只采集了I57和I58里面个别设备的数据。
- `location` - 位置，目前没有位置相关信息。
- `channel` - 频道，目前只采集了”BDF”这个频道的数据
- `startTime` - 获取数据的开始时间，**目前最多可以获取连续的5小时数据**，如果想要获取更长的连续数据，请分多次请求获取。
- `endTime` - 获取数据的结束时间。
- `filename` - 将获取的数据保存的文件名，**如果设置了 filename则不会有返回值。**

### 获取站点信息

```bash
inventory = client.get_stations([1], [1], [1])
print(inventory)

net = inventory[0]
print(net)
# 获取所有的站点信息
for station in net:
    print(station)
```

- `site` - 不能为空，列表形式，因为只有四个站点，最多就是[1,2,3,4]。
- `dataType` - 获取的数据类型，默认为全部获取，包括次声、电磁和地震，列表形式，因为只有三种数据类型，最多就是[1,2,3]
- `device` - 设备编号，默认为全部获取，列表形式，目前1个站点最多只有4个设备，所有最多就是[1,2,3,4]
- `filename` - 将获取去的数据保存的文件名，**如果设置了 filename则不会有返回值。**

### 获取事件信息

```bash
t1 = UTCDateTime("2023-02-19T04:12:10")
t2 = UTCDateTime("2023-02-19T09:12:10")
events = client.get_events(startTime="2023-02-19 12:12:10", endTime="2023-02-19 17:12:13")
print(events)

# 获取所有的事件信息
for event in events:
    print(event)
```

- `startTime` - 获取事件数据的开始时间。
- `endTime` - 获取事件数据的结束时间。
- `filename` - 将获取去的数据保存的文件名，**如果设置了 filename则不会有返回值。**