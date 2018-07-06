/*
* ע�⣬ pcap_next_ex() �ڳɹ�����ʱ�������EOF������£��᷵�ز�ͬ��ֵ
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
	pcap_if_t * allAdapters;//�������б�
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//���������
	struct pcap_pkthdr * packetHeader;
	struct tm *ltime;
	const u_char       * packetData; //���ݱ����ݵĻ���
	char errorBuffer[PCAP_ERRBUF_SIZE];//������Ϣ������
	char pcap_src_if_string[] = "rpcap://";
	char timestr[16];
	time_t local_tv_sec;

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
	//ѡ��Ҫ�������ݰ���������
	int adapterNumber;
	printf("Enter the adapter number between 1 and %d:", crtAdapter);
	// ʹ�ð�ȫ�� scanf����
	scanf_s("%d", &adapterNumber);
	if (adapterNumber < 1 || adapterNumber > crtAdapter)
	{
		printf("\nAdapter number out of range.\n");
		// �ͷ��������б�
		pcap_freealldevs(allAdapters);
		return -1;
	}

	adapter = allAdapters;
	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)
		adapter = adapter->next;
	// ��ָ��������
	adapterHandle = pcap_open(adapter->name, // name of the adapter
		65536,         // portion of the packet to capture
					   // 65536 guarantees that the whole 
					   // packet will be captured
		PCAP_OPENFLAG_PROMISCUOUS, // ��������ģʽ(promiscuous mode)�����о��������İ����ᱻץס
		1000,             // ��ȡ���ݵĳ�ʱʱ�䣨read timeout�� - ��λ�� 1 ����(millisecond)
						  // ���ó� 0 ��ζ�Ų��ᳬʱ��һֱ�ȴ����ݰ��� ���ó� -1 ���෴������������
		NULL,          // authentication on the remote machine
		errorBuffer    // error buffer
	);
	if (adapterHandle == NULL)
	{//ָ����������ʧ��
		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);
		// �ͷ��������б�
		pcap_freealldevs(allAdapters);
		return -1;
	}
	printf("\nCapture session started on  adapter %s\n", adapter->name);
	pcap_freealldevs(allAdapters);//�ͷ��������б�
								  // ��ʼ�������ݰ�


	int retValue;	// ��ȡ�������״̬��
	while ((retValue = pcap_next_ex(adapterHandle,
		&packetHeader,
		&packetData)) >= 0)
	{
		//��ʱʱ�䵽
		if (retValue == 0)
			continue;

		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
		local_tv_sec = packetHeader->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		//��ӡ�������ݰ�����Ϣ
		printf("\n================= ��������ݰ�ͷ����Ϣ ==================");
		printf("time stamp: %s\n", timestr);
		printf("length of packet: %d\n", packetHeader->len);
		printf("length of portion present: %d\n", packetHeader->caplen);
	}

	// �������쳣��� if we get here, there was an error reading the packets
	if (retValue == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(adapterHandle));
		return -1;
	}

	system("PAUSE");
	return 0;
}