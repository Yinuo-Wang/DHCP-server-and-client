#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <netinet/in.h>
#define MAX 300
#define ServIP "192.168.0.1"

struct Receive_packet                              //
{
	unsigned char header[240];
	unsigned char MsegType[3];
	unsigned char option[57];
};


struct DHCP_packet {
	char op;
	char htype;
	char hlen;
	char hops;
	char Transaction_ID[4];
	unsigned char seconds[2];
	unsigned char flags[2];
	unsigned char clint_addr[4];
	unsigned char your_addr[4];
	unsigned char server_addr[4];
	unsigned char router_addr[4];
	unsigned char client_hwaddr[6];
	unsigned char hwaddr_padding[10];
	char serverhost_name[64];
	char bootfile_name[128];
	char magic_cookie[4];
};

struct DHCP_discover
{
	struct DHCP_packet packet;
	char MsegType[3];
	char client_identifier[9];
	char class_identifier[10];
	char parameter_list[15];
	char End;
	//char padding[56];
};

struct DHCP_offer
{
	struct DHCP_packet packet;
	char MsegType[3];
	char server_identifier[6];
	char subnetmask[6];
	char router[6];
	char domain_name[6];
	char renewal_time[6];
	char rebinding_time[6];
	char End;
};

struct DHCP_request
{
	struct DHCP_packet packet;
	char MsegType[3];
	char requested_IP[6];
	char parameter_list[15];
	char End;

};

struct DHCP_ack
{ 
	struct DHCP_packet packet;
	char MsegType[3];
	char lease_time[6];
	char server_identifier[6];
	char subnetmask[6];
	char router[6];
	char domain_name[6];
	char renewal_time[6];
	char rebinding_time[6];
	char End;
};
struct DHCP_inform
{
	struct DHCP_packet packet;
	char MsegType[3];
	char parameter_list[15];
	char End;
};
struct DHCP_inform_ack
{
	struct DHCP_packet packet;
	char MsegType[3];
	char server_identifier[6];
	char subnetmask[6];
	char router[6];
	char domain_name[6];
	char End;	
};
struct DHCP_request_renewal
{
	struct DHCP_packet packet;
	char MsegType[3];
	char parameter_list[15];
	char End;

};
struct DHCP_nak
{
	struct DHCP_packet packet;
	char MsegType[3];
	char server_identifier[6];
	char End;
};
struct DHCP_release
{
	struct DHCP_packet packet;
	char MsegType[3];
	char server_identifier[6];
	char End;
};

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)  
{  
    short i;  
    unsigned char highByte, lowByte;  
  
    for (i = 0; i < sourceLen; i++)  
    {  
        highByte = source[i] >> 4;  
        lowByte = source[i] & 0x0f ;  
  
        highByte += 0x30;  
  
        if (highByte > 0x39)  
                dest[i * 2] = highByte + 0x07;  
        else  
                dest[i * 2] = highByte;  
  
        lowByte += 0x30;  
        if (lowByte > 0x39)  
            dest[i * 2 + 1] = lowByte + 0x07;  
        else  
            dest[i * 2 + 1] = lowByte;  
    }  
    return ;  
}  

void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)  
{  
    short i;  
    unsigned char highByte, lowByte;  
      
    for (i = 0; i < sourceLen; i += 2)  
    {  
        highByte = toupper(source[i]);  
        lowByte  = toupper(source[i + 1]);  
  
        if (highByte > 0x39)  
            highByte -= 0x37;  
        else  
            highByte -= 0x30;  
  
        if (lowByte > 0x39)  
            lowByte -= 0x37;  
        else  
            lowByte -= 0x30;  
  
        dest[i / 2] = (highByte << 4) | lowByte;  
    }  
    return ;  
} 

void HexByteToInt(const char* source, unsigned int* dest, int sourcelen)
{
    char middle[sourcelen];
    int i;
    for(i=0;i<sourcelen;i++)
    {
        middle[i] = source[sourcelen-1-i];
    }
    memcpy(dest,middle,sourcelen);
}
void IntToHexByte(unsigned int* source, char* dest, int destlen)
{
    char in[destlen];
    char out[destlen];
    memcpy(in,source,destlen);
    int i;
        for(i=0;i<destlen;i++)
    {
        out[i] = in[destlen-1-i];
    }
    out[destlen] = '\0';
    strcpy(dest,out);
}

void setCommonHeader(struct DHCP_packet *packet)
{
    char sendtransaction_ID[8] = "53a703dd";
    char seconds[4] = "0000";
    char flags[4] = "8000";
    char mac[12] = "08002745b743";
    char magic_cookie[8] = "63825363";
    packet->op = 0x01; //OP: request
    packet->htype = 0x01;  //Hardware type: Ethernet(0x01)
    packet->hlen = 0x06; //Hardware address length: 6
    packet->hops = 0x00;  //Hops: 0
        /*Transaction_ID: 0x53a703dd*/
    HexStrToByte(sendtransaction_ID,packet->Transaction_ID,8);
    HexStrToByte(seconds,packet->seconds,4); //seconds elapsed: 0strcpy(flags,"8000");
    HexStrToByte(flags,packet->flags,4); //Bootp flags: 0x0000, Unicast
    HexStrToByte(mac,packet->client_hwaddr,12);//Client MAC address: 0x08002745b743
    HexStrToByte(magic_cookie,packet->magic_cookie,8);//Magic cookie: DHCP

}


void setLocalIpAddr(char *ipAddr)
{
    unsigned char command[100];
    sprintf((char *)command, "ifconfig %s %s", "eth1", ipAddr);
    system(command);
}

void getLocalAddr(unsigned char *ipAddr)
{
    int fd;
    struct ifreq ifr;
     
    char iface[] = "eth1";
     
    fd = socket(AF_INET, SOCK_DGRAM, 0);
 
    ifr.ifr_addr.sa_family = AF_INET;
 
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
 
    ioctl(fd, SIOCGIFADDR, &ifr);
 
    close(fd);
   
    strcpy(ipAddr,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
}


int main(int argc, const char *argv[])
{
	int i;
	int times=0;
	struct DHCP_packet client;
	struct DHCP_discover discover;
	struct DHCP_offer offer;
	struct DHCP_request request;
	struct DHCP_ack ack;
	struct Receive_packet receive;
	struct DHCP_request_renewal request_renewal;
	struct DHCP_nak nak;
	struct DHCP_inform inform;
	struct DHCP_inform_ack inform_ack;
	struct DHCP_release release;
	//struct ippool ip[4];

	struct in_addr client_addr;
	struct in_addr your_addr;
	struct in_addr server_addr;
	struct in_addr router_addr;
	
	char Buffer[1024];
	char ClntIP[30];
	char wrongIP[30];
	struct sockaddr_in dhcpServAddr;
	struct sockaddr_in dhcpClntAddr;
	struct sockaddr_in fromAddr;
	unsigned int serAddrLen;
	int recvMsgSize;
	int sock;
	int dhcpServPort = 67;
	int dhcpClntPort = 68;
	char sendtransaction_ID[8] = "53a703dd";
	int sendseconds;
	int sendflags;
	char seconds[4] = "0000";
	char flags[4] = "0000";
	char mac[12] = "08002745b743";
	char magic_cookie[8] = "63825363";
	char MsegType[6] = "350101";
	char client_identifier[18] = "3d070108002745b743";
	char server_identifier[12] = "3604c0a80001";
	char class_identifier[20] = "3c084d53465420352e30";
	char parameter_list[30] = "370d0103060f1f212b2c2e2f79f9fc";
	char requested_IP[4] = "3204";
	int lease_time;

/*user input*/
	if (argc < 2)
	{
		printf("Usage: %s --<action> \n", argv[0]);
		exit(1);
	}

	getLocalAddr(ClntIP);                                      //获取网卡1的ip地址存到ClntIP

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	printf("socket() failed.\n");
    printf("socket build successfully\n");
	memset(&dhcpClntAddr, 0, sizeof(dhcpClntAddr));
	dhcpClntAddr.sin_family = AF_INET;
	dhcpClntAddr.sin_addr.s_addr =  htonl(INADDR_ANY);
	dhcpClntAddr.sin_port =htons(dhcpClntPort);


	memset(&dhcpServAddr, 0, sizeof(dhcpServAddr));
	dhcpServAddr.sin_family = AF_INET;
	dhcpServAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
	dhcpServAddr.sin_port =htons(dhcpServPort);

	struct sockaddr_in ieth1 ;
	memset(&ieth1,0,sizeof(ieth1));

	i=1;
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);
	/*allow socket to broadcast */
	setsockopt(sock,SOL_SOCKET,SO_BROADCAST,&i,len);
	/*set socket to interface eth1 */
	if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0)
	{
		printf("bind socket to eth1 error\n");
	}
	

	if ((bind(sock, (struct sockaddr *) &dhcpClntAddr, sizeof(dhcpClntAddr))) < 0)
	{
		printf("bind() failed.\n");
	}
	
	printf("bind successfully\n");
	recvMsgSize = 300;
	serAddrLen = sizeof(dhcpServAddr);

	tt:
	
	//判断输入
	if(strcmp(argv[1],"--default") == 0)
{
	

	printf("eth1 IP is: %s\n",ClntIP);
/*DHCP_discover*/
	memset(&discover,0,sizeof(discover));
	setCommonHeader(&discover.packet);       //前240个header

	strcpy(MsegType,"350101");
	HexStrToByte(MsegType,discover.MsegType,6);
	/*client_identifier*/
	HexStrToByte(client_identifier,discover.client_identifier,18);
	HexStrToByte(class_identifier,discover.class_identifier,20);
	HexStrToByte(parameter_list,discover.parameter_list,30);

		discover.End = 0xff;
	
		memcpy(Buffer,&discover,sizeof(discover));
		printf("Buffer is: %s\n",Buffer);
		dhcpServAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
		if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
		{
			printf("sendto() sent a different number of bytes than expected.\n");
		}
			printf("Send successfully\n");
	

/*DHCP_offer*/
		memset(Buffer,0,sizeof(Buffer));
		memset(&offer,0,sizeof(offer));
		if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
		printf("recvfrom() failed.\n");

		memcpy(&offer,Buffer,sizeof(offer));
		char transaction_ID[8];
		ByteToHexStr(offer.packet.Transaction_ID,transaction_ID,4);
		printf("tranaction_id is: %s\n",transaction_ID);
		printf("offer.packet.your_addr is: %s\n",inet_ntoa(* (struct in_addr *)(offer.packet.your_addr))); 
		ByteToHexStr(offer.MsegType,MsegType,3);
		printf("Message type is: %s\n",MsegType);


/*DHCP_request*/
	memset(&request,0,sizeof(request));
	setCommonHeader(&request.packet);
	memset(Buffer,0,sizeof(Buffer));
	HexStrToByte(requested_IP,&request.requested_IP[0],4);
	memcpy(&request.requested_IP[2],offer.packet.your_addr,4);

	memcpy(request.packet.your_addr,&your_addr.s_addr,4);
	memcpy(request.packet.server_addr,&server_addr.s_addr,4);
	strcpy(MsegType,"350103");
	HexStrToByte(MsegType,request.MsegType,6);
	strcpy(parameter_list,"370d0103060f1f212b2c2e2f79f9fc");
	HexStrToByte(parameter_list,request.parameter_list,30);
	request.End = 0xff;

	memcpy(Buffer,&request,sizeof(request));
	dhcpServAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}
	
/*DHCP_ack*/	
	memset(Buffer,0,sizeof(Buffer));
	memset(&ack,0,sizeof(ack));
	if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
	{
		printf("recvfrom() failed.\n");	
	}
	memcpy(&ack,Buffer,sizeof(ack));
	ByteToHexStr(ack.MsegType,MsegType,3);
	printf("Message type is: %s\n",MsegType);

	HexByteToInt(&ack.lease_time[2],&lease_time,4);
	printf("lease_time is: %d\n",lease_time);

	printf("ie1 ip address will be: %s\n",inet_ntoa(* (struct in_addr *)(ack.packet.your_addr)));
	setLocalIpAddr(inet_ntoa(* (struct in_addr *)(ack.packet.your_addr)));


/*DHCP_autorenew*/
		if(argc == 3 && strcmp(argv[2],"sleep") == 0)
		{
			loop:
			sleep(lease_time/2);
			memset(&request_renewal,0,sizeof(request_renewal));
			setCommonHeader(&request_renewal.packet);
			memset(Buffer,0,sizeof(Buffer));
			strcpy(flags,"0000");
			HexStrToByte(flags,request_renewal.packet.flags,4);
			client_addr.s_addr = inet_addr((inet_ntoa(* (struct in_addr *)(ack.packet.your_addr))));
			memcpy(request_renewal.packet.clint_addr,&client_addr.s_addr,4);

			strcpy(MsegType,"350103");
			HexStrToByte(MsegType,request_renewal.MsegType,6);
			HexStrToByte(parameter_list,request_renewal.parameter_list,30);
			request_renewal.End = 0xff;

			memcpy(Buffer,&request_renewal,sizeof(request_renewal));
			dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
			if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
			{
				printf("sendto() sent a different number of bytes than expected.\n");
			}

			memset(&ack,0,sizeof(ack));
			memset(Buffer,0,sizeof(Buffer));
			if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
			{
				printf("recvfrom() failed.\n");	
			}
			memcpy(&ack,Buffer,sizeof(ack));
			ByteToHexStr(ack.MsegType,MsegType,3);
			printf("Message type is: %s\n",MsegType);
			HexByteToInt(&ack.lease_time[2],&lease_time,4);
			printf("lease_time is: %d\n",lease_time);
			goto loop;
		}
}




	if(strcmp(argv[1],"--inform") == 0)
	{
/*DHCP_inform*/
	memset(&inform,0,sizeof(inform));
	setCommonHeader(&inform.packet);
	memset(Buffer,0,sizeof(Buffer));
	inform.packet.op = 0x01;
	strcpy(flags,"0000");
	HexStrToByte(flags,inform.packet.flags,4);
	client_addr.s_addr = inet_addr(ClntIP);
	memcpy(inform.packet.clint_addr,&client_addr.s_addr,4);

	strcpy(MsegType,"350108");
	HexStrToByte(MsegType,inform.MsegType,6);
	HexStrToByte(parameter_list,inform.parameter_list,30);
	inform.End = 0xff;
	memcpy(Buffer,&inform,sizeof(inform));
	printf("The ack server ip address is wrong? %s\n",inet_ntoa(* (struct in_addr *)(ack.packet.server_addr)));

	dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}

	memset(Buffer,0,sizeof(Buffer));
	memset(&inform_ack,0,sizeof(inform_ack));
	if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
	{
		printf("recvfrom() failed.\n");	
	}
	memcpy(&inform_ack,Buffer,sizeof(inform_ack));
	ByteToHexStr(inform_ack.MsegType,MsegType,3);
	printf("Message type is: %s\n",MsegType);
	}

	if(strcmp(argv[1],"--renew")==0 && argc==2)
	{
		
/*DHCP_request renewal*/
	memset(&request_renewal,0,sizeof(request_renewal));
	setCommonHeader(&request_renewal.packet);
	memset(Buffer,0,sizeof(Buffer));
	strcpy(flags,"0000");
	HexStrToByte(flags,request_renewal.packet.flags,4);
	client_addr.s_addr = inet_addr(ClntIP);
	memcpy(request_renewal.packet.clint_addr,&client_addr.s_addr,4);

	strcpy(MsegType,"350103");
	HexStrToByte(MsegType,request_renewal.MsegType,6);
	HexStrToByte(parameter_list,request_renewal.parameter_list,30);
	request_renewal.End = 0xff;

	memcpy(Buffer,&request_renewal,sizeof(request_renewal));
	dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}

/*ack*/
	memset(&ack,0,sizeof(ack));
	memset(Buffer,0,sizeof(Buffer));
	if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
	{
		printf("recvfrom() failed.\n");	
	}
	memcpy(&ack,Buffer,sizeof(ack));
	ByteToHexStr(ack.MsegType,MsegType,3);
	printf("Message type is: %s\n",MsegType);
	HexByteToInt(&ack.lease_time[2],&lease_time,4);
	printf("lease_time is: %d\n",lease_time);
	}

	if(strcmp(argv[1],"--renewal")==0 && argc==3)
	{
		
/*DHCP_request renew wrong*/
	strcpy(wrongIP,argv[2]);
	memset(&request_renewal,0,sizeof(request_renewal));
	setCommonHeader(&request_renewal.packet);
	memset(Buffer,0,sizeof(Buffer));
	strcpy(flags,"0000");
	HexStrToByte(flags,request_renewal.packet.flags,4);
	client_addr.s_addr = inet_addr(wrongIP);
	memcpy(request_renewal.packet.clint_addr,&client_addr.s_addr,4);
	strcpy(MsegType,"350103");
	HexStrToByte(MsegType,request_renewal.MsegType,6);
	HexStrToByte(parameter_list,request_renewal.parameter_list,30);
	request_renewal.End = 0xff;
	memcpy(Buffer,&request_renewal,sizeof(request_renewal));
	dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}
/*nak*/

	memset(&nak,0,sizeof(nak));
	memset(Buffer,0,sizeof(Buffer));
	if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *)&dhcpServAddr, &serAddrLen)) < 0)
	{
		printf("recvfrom() failed.\n");	
	}

	setLocalIpAddr("0.0.0.0");

	memcpy(&nak,Buffer,sizeof(nak));
	ByteToHexStr(nak.MsegType,MsegType,3);
	printf("Message type is: %s\n",MsegType);
	argv[1] = "--default";
	goto tt;
	}

//release
	if(strcmp(argv[1],"--release") == 0)
	{
		memset(&release,0,sizeof(release));
		setCommonHeader(&release.packet);
		memset(Buffer,0,sizeof(Buffer));
		client_addr.s_addr = inet_addr(ClntIP);
		memcpy(release.packet.clint_addr,&client_addr.s_addr,4);
		strcpy(MsegType,"350107");
		HexStrToByte(MsegType,release.MsegType,6);
		HexStrToByte(server_identifier,release.server_identifier,12);
		release.End = 0xff;
		memcpy(Buffer,&release,sizeof(release));
		dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}
		setLocalIpAddr("0.0.0.0");

	}


	if(strcmp(argv[1],"--serverdown") == 0)
	{
		lease_time = 16;
		sleep(lease_time/2);
		memset(&request_renewal,0,sizeof(request_renewal));
		setCommonHeader(&request_renewal.packet);
		memset(Buffer,0,sizeof(Buffer));
		strcpy(flags,"0000");
		HexStrToByte(flags,request_renewal.packet.flags,4);
		client_addr.s_addr = inet_addr(ClntIP);
		memcpy(request_renewal.packet.clint_addr,&client_addr.s_addr,4);

		strcpy(MsegType,"350103");
		HexStrToByte(MsegType,request_renewal.MsegType,6);
		HexStrToByte(parameter_list,request_renewal.parameter_list,30);
		request_renewal.End = 0xff;

		memcpy(Buffer,&request_renewal,sizeof(request_renewal));
		dhcpServAddr.sin_addr.s_addr = inet_addr(ServIP);
		if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
		{
			printf("sendto() sent a different number of bytes than expected.\n");
		}

		sleep(lease_time*3/8);
		memset(&request_renewal,0,sizeof(request_renewal));
		setCommonHeader(&request_renewal.packet);
		memset(Buffer,0,sizeof(Buffer));
		strcpy(flags,"8000");
		HexStrToByte(flags,request_renewal.packet.flags,4);
		client_addr.s_addr = inet_addr(ClntIP);
		memcpy(request_renewal.packet.clint_addr,&client_addr.s_addr,4);

		strcpy(MsegType,"350103");
		HexStrToByte(MsegType,request_renewal.MsegType,6);
		HexStrToByte(parameter_list,request_renewal.parameter_list,30);
		request_renewal.End = 0xff;

		memcpy(Buffer,&request_renewal,sizeof(request_renewal));
		dhcpServAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
		if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
		{
			printf("sendto() sent a different number of bytes than expected.\n");
		}

		sleep(lease_time*1/8);

		setLocalIpAddr("0.0.0.0");
		memset(&discover,0,sizeof(discover));
		setCommonHeader(&discover.packet);

		strcpy(MsegType,"350101");
		HexStrToByte(MsegType,discover.MsegType,6);
		/*client_identifier*/
		HexStrToByte(client_identifier,discover.client_identifier,18);
		HexStrToByte(class_identifier,discover.class_identifier,20);
		HexStrToByte(parameter_list,discover.parameter_list,30);

		discover.End = 0xff;
	
		memcpy(Buffer,&discover,sizeof(discover));
		printf("Buffer is: %s\n",Buffer);
		dhcpServAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
		if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpServAddr,sizeof(dhcpServAddr))) != recvMsgSize)
		{
			printf("sendto() sent a different number of bytes than expected.\n");
		}else{
		printf("Send successfully\n");}


	}

}

