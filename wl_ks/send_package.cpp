#include <pcap.h>
#include <tchar.h>
int _cmain(int argc, _TCHAR* argv[])
{
	pcap_if_t * allAdapters;//�������б�
	pcap_if_t * adapter;
	pcap_t           * adapterHandle;//���������
	u_char         packet[20]; //�����͵����ݷ��
	char pcap_src_if_string[] = "rpcap://";

	char errorBuffer[PCAP_ERRBUF_SIZE];//������Ϣ������
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL,
		&allAdapters, errorBuffer) == -1)
	{//�����������ӵ���������������
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);
		return -1;
	}
	if (allAdapters == NULL)
	{//���������κ�������
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
	//ѡ��������
	int adapterNumber;
	printf("Enter the adapter number between 1 and %d:", crtAdapter);
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
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,             // read timeout - 1 millisecond
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
	pcap_freealldevs(allAdapters);//�ͷ��������б�
								  //�������ݷ��
	// ����Ŀ���MAC��ַΪ01 : 01 : 01 : 01 : 01 : 01
	packet[0] = 0x01;
	packet[1] = 0x01;
	packet[2] = 0x01;
	packet[3] = 0x01;
	packet[4] = 0x01;
	packet[5] = 0x01;
	// ����Դ��MAC��ַΪ02 : 02 : 02 : 02 : 02 : 02
	packet[6] = 0x02;
	packet[7] = 0x02;
	packet[8] = 0x02;
	packet[9] = 0x02;
	packet[10] = 0x02;
	packet[11] = 0x02;
	// ���÷��������������
	for (int index = 12; index < 20; index++)
	{
		packet[index] = 0xC4;
	}
	//�������ݷ��,������ݰ��ɹ����ͣ�����ֵΪ0������Ϊ-1��
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