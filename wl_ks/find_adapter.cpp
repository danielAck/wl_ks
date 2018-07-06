#include <pcap.h>
#include <tchar.h>

int _tmain(int argc, _TCHAR* argv[])
{

	// pcap_if ��һ������ṹ
	pcap_if_t * allAdapters;//�������б�
	pcap_if_t * adapter;
	char errorBuffer[PCAP_ERRBUF_SIZE];//������Ϣ������
	char pcap_src_if_string[] = "rpcap://";

	if (pcap_findalldevs_ex(pcap_src_if_string, NULL,
		&allAdapters, errorBuffer) == -1)
	{//�����������ӵ���������������
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);
		return -1;
	}
	if (allAdapters == NULL)
	{//�������κ�������
		printf("\nNo adapters found! Make sure WinPcap is installed.\n");
		return 0;
	}
	int crtAdapter = 0;
	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)
	{//����������������Ϣ(���ƺ�������Ϣ)
		printf("\n%d.%s ", ++crtAdapter, adapter->name);
		printf("-- %s\n", adapter->description);
	}
	printf("\n");

	// Ҫ��ס��������������豸�б��ʹ�ã�����Ҫ���� pcap_freealldevs() ��������ռ�õ��ڴ���Դ�ͷ�
	pcap_freealldevs(allAdapters);//�ͷ��������б�
	system("PAUSE");
	return 0;
}