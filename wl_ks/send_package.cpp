#include <pcap.h>
#include <tchar.h>
int _cmain(int argc, _TCHAR* argv[])
{
	pcap_if_t * allAdapters;//适配器列表
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//适配器句柄
	u_char         packet[20]; //待发送的数据封包
	char pcap_src_if_string[] = "rpcap://";

	char errorBuffer[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL,
		&allAdapters, errorBuffer) == -1)
	{//检索机器连接的所有网络适配器
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);
		return -1;
	}
	if (allAdapters == NULL)
	{//不存在人任何适配器
		printf("\nNo adapters found! Make sure WinPcap is installed.\n");
		return 0;
	}
	int crtAdapter = 0;
	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)
	{//遍历输入适配器信息(名称和描述信息)
		printf("\n%d.%s ", ++crtAdapter, adapter->name);
		printf("-- %s\n", adapter->description);
	}
	printf("\n");
	//选择适配器
	int adapterNumber;
	printf("Enter the adapter number between 1 and %d:", crtAdapter);
	scanf_s("%d", &adapterNumber);
	if (adapterNumber < 1 || adapterNumber > crtAdapter)
	{
		printf("\nAdapter number out of range.\n");
		// 释放适配器列表
		pcap_freealldevs(allAdapters);
		return -1;
	}
	adapter = allAdapters;
	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)
		adapter = adapter->next;
	// 打开指定适配器
	adapterHandle = pcap_open(adapter->name, // name of the adapter
		65536,         // portion of the packet to capture
					   // 65536 guarantees that the whole 
					   // packet will be captured
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,             // read timeout - 1 millisecond
		NULL,          // authentication on the remote machine
		errorBuffer    // error buffer
	);
	if (adapterHandle == NULL)
	{//指定适配器打开失败
		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);
		// 释放适配器列表
		pcap_freealldevs(allAdapters);
		return -1;
	}
	pcap_freealldevs(allAdapters);//释放适配器列表
								  //创建数据封包
	// 设置目标的MAC地址为01 : 01 : 01 : 01 : 01 : 01
	packet[0] = 0x01;
	packet[1] = 0x01;
	packet[2] = 0x01;
	packet[3] = 0x01;
	packet[4] = 0x01;
	packet[5] = 0x01;
	// 设置源的MAC地址为02 : 02 : 02 : 02 : 02 : 02
	packet[6] = 0x02;
	packet[7] = 0x02;
	packet[8] = 0x02;
	packet[9] = 0x02;
	packet[10] = 0x02;
	packet[11] = 0x02;
	// 设置封包其他部分内容
	for (int index = 12; index < 20; index++)
	{
		packet[index] = 0xC4;
	}
	//发送数据封包,如果数据包成功发送，返回值为0，否则为-1。
	if (pcap_sendpacket(adapterHandle, // the adapter handle
		packet, // the packet
		20 // the length of the packet
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adapterHandle));
		return -1;
	}
	system("PAUSE");
	return 0;
}