/*
* 注意， pcap_next_ex() 在成功，超时，出错或EOF的情况下，会返回不同的值
*	
*	1 if the packet has been read without problems
*   0 if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
*	-1 if an error occurred
*	-2 if EOF was reached reading from an offline capture
*/

#include <pcap.h>
#include <tchar.h>
int _bmain(int argc, _TCHAR* argv[])
{
	pcap_if_t * allAdapters;//适配器列表
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//适配器句柄
	struct pcap_pkthdr * packetHeader;
	struct tm *ltime;
	const u_char       * packetData; //数据报数据的缓冲
	char errorBuffer[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	char pcap_src_if_string[] = "rpcap://";
	char timestr[16];
	time_t local_tv_sec;

	if (pcap_findalldevs_ex(pcap_src_if_string, NULL,
		&allAdapters, errorBuffer) == -1)
	{//检索机器连接的所有网络适配器
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);
		return -1;
	}
	if (allAdapters == NULL)
	{//不存在任何适配器
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
	//选择要捕获数据包的适配器
	int adapterNumber;
	printf("Enter the adapter number between 1 and %d:", crtAdapter);
	// 使用安全的 scanf函数
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
		PCAP_OPENFLAG_PROMISCUOUS, // 开启混杂模式(promiscuous mode)，所有经过网卡的包都会被抓住
		1000,             // 读取数据的超时时间（read timeout） - 单位是 1 毫秒(millisecond)
						  // 设置成 0 意味着不会超时，一直等待数据包， 设置成 -1 则相反，会立即返回
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
	printf("\nCapture session started on  adapter %s\n", adapter->name);
	pcap_freealldevs(allAdapters);//释放适配器列表
								  // 开始捕获数据包


	int retValue;	// 读取捕获包的状态码
	while ((retValue = pcap_next_ex(adapterHandle,
		&packetHeader,
		&packetData)) >= 0)
	{
		//超时时间到
		if (retValue == 0)
			continue;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = packetHeader->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		//打印捕获数据包的信息
		printf("\n================= 捕获的数据包头部信息 ==================");
		printf("time stamp: %s\n", timestr);
		printf("length of packet: %d\n", packetHeader->len);
		printf("length of portion present: %d\n", packetHeader->caplen);
	}

	// 出现了异常情况 if we get here, there was an error reading the packets
	if (retValue == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(adapterHandle));
		return -1;
	}

	system("PAUSE");
	return 0;
}