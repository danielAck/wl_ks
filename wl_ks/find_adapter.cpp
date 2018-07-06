#include <pcap.h>
#include <tchar.h>

int _tmain(int argc, _TCHAR* argv[])
{

	// pcap_if 是一个链表结构
	pcap_if_t * allAdapters;//适配器列表
	pcap_if_t * adapter;
	char errorBuffer[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	char pcap_src_if_string[] = "rpcap://";

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

	// 要记住，当我们完成了设备列表的使用，我们要调用 pcap_freealldevs() 函数将其占用的内存资源释放
	pcap_freealldevs(allAdapters);//释放适配器列表
	system("PAUSE");
	return 0;
}