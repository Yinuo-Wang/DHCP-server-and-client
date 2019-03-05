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

struct Receive_packet                                   //sever 
{
	unsigned char header[240];
	unsigned char MesgType[3];                          //最后一位表示报的类型
	unsigned char option[57];
};
struct DHCP_packet                                     //DHCP header结构
{
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
	char magic_cookie[4];                              //4位固定数（识别option）
};

struct DHCP_discover
{
	struct DHCP_packet packet;
	char MsegType[3];
	char client_identifier[9];
	char class_identifier[10];
	char parameter_list[15];                           //固定
	char End;
};

struct DHCP_offer
{
	struct DHCP_packet packet;
	char MsegType[3];
	char server_identifier[6];
	char subnetmask[6];
	char router[6];                                   //server IP地址
	char domain_name[6];                              //域名——server 地址
	char renewal_time[6];
	char rebinding_time[6];
	char End;
	//char padding[56];
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
	char lease_time[6];                         // 特有
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
struct DHCP_inform_ack                             //inform单独ACK
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


struct ipaddresspool             //从dhcp config取IP地址
{
	char ipaddr[255];
	int available;
    char option[255];
};
struct ipleasepool               //存dhcp.lease
{
	char ipaddr[14];
	char clientmac[12];
	int lease_time;
};

//data transformation?

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)         //16进制比特拆成字符串，出=2入
{  
    short i;  
    unsigned char highByte, lowByte;  
  
    for (i = 0; i < sourceLen; i++)  
    {  
        highByte = source[i] >> 4;  
        lowByte = source[i] & 0x0f;  
  
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
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)                  //magic cookie 
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
void HexByteToInt(const char* source, unsigned int* dest, int sourcelen)   //ipadress lease time 转换
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
    memcpy(dest,out,destlen);
}

int main(int argc, const char *argv[])
//argc是命令行总的参数个数,argv[]是argc个参数，其中第0个参数是程序的全名，以后的参数; 命令行后面跟的用户输入的参数
{
	static int times=1;
	int i;
	int choose;
	//structures
	struct Receive_packet recvpacket;
	struct DHCP_packet client;
	struct DHCP_discover discover;
	struct DHCP_offer offer;
	struct DHCP_request request;
	struct DHCP_ack ack;
	struct DHCP_request_renewal request_renewal;
	struct DHCP_nak nak;
	struct DHCP_inform inform;
	struct DHCP_inform_ack inform_ack;
	struct DHCP_release release;
	struct ipaddresspool ip[4];
	struct ipleasepool iplease[4];

	//ipv4 address
	struct in_addr client_addr;
	struct in_addr your_addr;
	struct in_addr server_addr;
	struct in_addr router_addr;

	char Buffer[1024];                                   //收发send to、receive from

	long int t;

	/* struct sockaddr_in {
    /*   short int sin_family;              /* Address family */
    /* unsigned short int sin_port;       /* Port number */
    /* struct in_addr sin_addr;           /* Internet address */
    /* unsigned char sin_zero[8];         /* Same size as struct sockaddr */
    /* } */
	struct sockaddr_in dhcpServAddr;                    //UDP
	struct sockaddr_in dhcpClntAddr;
	unsigned int cliAddrLen;
	int recvMsgSize;
	int sock;
	int dhcpServPort = 67;
	int dhcpClntPort = 68;

	char MsegType[6] = "350102";
	char server_identifier[12] = "3604c0a80001";
	char subnetmask[12] = "0104ffffff00";
	
	char router[12] = "0304c0a80001";
	char domain_name[12] = "0604c0a80001";
	char lease_time_head[4] = "3304";
	char lease_time_time[4];
	char lease_time[6];

	if (argc < 2)                                               //判断输入个数
	{
		printf("Usage: %s leasetime \n", argv[0]);
		exit(1);
	}
	if (atoi(argv[1]) == 0)                                     //能否转化成整数
	{
		printf("lease time illegal");
		exit(1);
	}
	
//atoi() 函数用来将字符串转换成整数(int)，其原型为：
//int atoi (const char * str);
//[函数说明]atoi() 函数会扫描参数 str 字符串，
//跳过前面的空白字符（例如空格，tab缩进等，可以通过 isspace() 函数来检测），
//直到遇上数字或正负符号才开始做转换，而再遇到非数字或字符串结束时('\0')才结束转换，
//并将结果返回。
	
/*输入lease time存入lease_time*/
	HexStrToByte(lease_time_head,lease_time,4);                 //lease_time_head和lease_time_time 附给lease——time              
	int x = atoi(argv[1]);
	printf("x is: %d \n",x);
	//指针传递
	IntToHexByte(&x,lease_time_time,4);                         //x赋值给lease_time_time 4字节
	memcpy(&lease_time[2],lease_time_time,4);

	
	server_addr.s_addr = inet_addr("192.168.0.1");
	
/*socket声明*/
if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	printf("socket() failed.\n");
	memset(&dhcpServAddr, 0, sizeof(dhcpServAddr));
	dhcpServAddr.sin_family = AF_INET;                         //TCPIP协议
	dhcpServAddr.sin_addr.s_addr = htonl(INADDR_ANY);          //用无符号长整型数据来表示IP地址.此时,用的是s_nu数据成员,s_un是一个结构体,
	                                                           //其中只有一个数据成员,即s_addr.变量.sin_addr.S_un.S.addr=htonl("IP地址");
	dhcpServAddr.sin_port =htons(dhcpServPort);

//发广播包
	i=1;
	struct ifreq if_eth1;                                      //配置ip地址，激活接口，配置MTU等接口信息
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);
	/*allow socket to broadcast ?*/
	setsockopt(sock,SOL_SOCKET,SO_BROADCAST,&i,len);
	/*set socket to interface eth1 */
	if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0)
	{
		printf("bind socket to eth1 error\n");
	}


  /*Listen to port 67 */
	if ((bind(sock, (struct sockaddr *) &dhcpServAddr, sizeof(dhcpServAddr))) < 0)
	{
	printf("bind() failed.\n");
	}else{
	printf("bind successfully\n");}

//读取ip地址
	FILE *fd1;
	fd1=fopen("dhcp.txt","r");
	i=0;
	while(fscanf(fd1,"%s %d %s",ip[i].ipaddr,&ip[i].available,ip[i].option)!=EOF)
	{
		i++;
	}
	fclose(fd1);
	printf("get ip is: %s\n",ip[0].ipaddr);

//判断ip有没有被分配，分配的为1,release 为0
for(;;)
{

	for(i=0;i<4;i++)
	{
		if(ip[i].available == 0)
		{
			choose = i;
			break;
		}
	}


	memset(Buffer,0,sizeof(Buffer));                //清空地址
	cliAddrLen = sizeof(dhcpClntAddr);
//UDP收发
	if ((recvMsgSize = recvfrom(sock, Buffer, MAX,0,(struct sockaddr *) &dhcpClntAddr, &cliAddrLen)) < 0)
	{
	printf("recvfrom() failed.\n");
	}else{
	printf("Receive successfully\n");}
	memcpy(&recvpacket,Buffer,sizeof(recvpacket));


//判断包类型
	if(recvpacket.MesgType[2] == 0x01)
	{
 
/*DHCP_Offer*/
	printf("DHCP_offer part:------------\n");
	memset(&offer,0,sizeof(offer));
	memcpy(&offer.packet,Buffer,240);
	memset(Buffer,0,sizeof(Buffer));

	your_addr.s_addr = inet_addr(ip[choose].ipaddr);
	printf("choose is: %d\n",choose);
	printf("get ip is: %s\n",ip[choose].ipaddr);
	
	//memcpy(client.clint_addr,&client_addr.s_addr,4);

	offer.packet.op = 0x02;                                       //op 01 request 02reply
	memcpy(offer.packet.your_addr,&your_addr.s_addr,4);
	printf("the address is wrong? %s\n",inet_ntoa(server_addr));
	memset(&request_renewal,0,sizeof(request_renewal));
	strcpy(MsegType,"350102");
	HexStrToByte(MsegType,offer.MsegType,6);
	
	HexStrToByte(server_identifier,offer.server_identifier,12);
	HexStrToByte(subnetmask,offer.subnetmask,12);
	
	HexStrToByte(router,offer.router,12);
	
	HexStrToByte(domain_name,offer.domain_name,12);
	offer.End = 0xff;                    //11111111

	memcpy(Buffer,&offer,sizeof(offer));
	dhcpClntAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
//发送广播包
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpClntAddr,sizeof(dhcpClntAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}


	}

//request
	if(recvpacket.MesgType[2] == 0x03)
	{
		int anack = 0;
/*DHCP_Request*/
		memset(&ack,0,sizeof(ack));
		memset(&nak,0,sizeof(nak));
	memcpy(&request,Buffer,sizeof(request));

	//client 第一位=0 offer后面的request； 不是0 renew的request
	if(request.packet.clint_addr[0] == 0x00)
	{
		/*DHCP_Ack_request*/
		memcpy(&ack.packet,Buffer,240);
		memset(Buffer,0,sizeof(Buffer));
		ack.packet.op = 0x02;
		//your_addr.s_addr = inet_addr(ip[choose].ipaddr);
		//server_addr.s_addr = inet_addr("192.168.0.1");
		memcpy(ack.packet.your_addr,&request.requested_IP[2],4);

		strcpy(MsegType,"350105");
		HexStrToByte(MsegType,ack.MsegType,6);
		memcpy(ack.lease_time,lease_time,6);
		HexStrToByte(server_identifier,ack.server_identifier,12);
		HexStrToByte(subnetmask,ack.subnetmask,12);

		HexStrToByte(router,ack.router,12);
		HexStrToByte(domain_name,ack.domain_name,12);
		ack.End = 0xff;
		anack = 0;
		ip[choose].available = 1;

//写入dhcp.lease
		int fd2;
		char filewriter[45];
		memset(iplease,0,sizeof(iplease));
		memset(filewriter,0,sizeof(filewriter));
		if((fd2=open("dhcp.lease",O_CREAT|O_RDWR|O_APPEND))==-1)
		printf("Error in opening");
		memcpy(iplease[0].ipaddr,inet_ntoa(* (struct in_addr *)(ack.packet.your_addr)),13);
		iplease[0].ipaddr[13] = '\0';
		ByteToHexStr(ack.packet.client_hwaddr,iplease[0].clientmac,6);

		printf("iplease.clientmac is :%s\n",iplease[0].clientmac);

		HexByteToInt(&ack.lease_time[2],&iplease[0].lease_time,4);

		printf("iplease.lease_time is :%d\n",iplease[0].lease_time);

		sprintf(filewriter,"%s %s %d\n",iplease[0].ipaddr,iplease[0].clientmac,iplease[0].lease_time);
		int strlength = strlen(filewriter);
		
		if(write(fd2,filewriter,strlength)!=strlength)
		{
			printf("filewriter write error\n");
		}
		close(fd2);

		dhcpClntAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
		
	}
	else
	{
		/*DHCP_Ack_request_renewal*/
		char test_addr[4];
		if(strcmp(request.packet.clint_addr,offer.packet.your_addr) == 0)   //offer的地址和request地址是不是相同的，相同返回0
		{
			memcpy(&ack.packet,&request.packet,240);
			//memset(Buffer,0,sizeof(Buffer));
			ack.packet.op = 0x02;
			memcpy(ack.packet.your_addr,request.packet.clint_addr,4);

		strcpy(MsegType,"350105");
		HexStrToByte(MsegType,ack.MsegType,6);
		memcpy(ack.lease_time,lease_time,6);
		HexStrToByte(server_identifier,ack.server_identifier,12);
		HexStrToByte(subnetmask,ack.subnetmask,12);
	
		HexStrToByte(router,ack.router,12);
	
		HexStrToByte(domain_name,ack.domain_name,12);
	
		ack.End = 0xff;
		anack = 0;
		dhcpClntAddr.sin_addr.s_addr = inet_addr(inet_ntoa(* (struct in_addr *)(request.packet.clint_addr)));
		//数据类型转换
		}
		else
		{
	    /*DHCP_Nak*/
		printf("May be the address problem\n");
		memcpy(&nak.packet,&request.packet,240);
		//memset(Buffer,0,sizeof(Buffer));
		nak.packet.op = 0x02;
		client_addr.s_addr = inet_addr("0.0.0.0");
		your_addr.s_addr = inet_addr("0.0.0.0");
		//server_addr.s_addr = inet_addr("0.0.0.0");
		memcpy(nak.packet.clint_addr,&client_addr.s_addr,4);
		memcpy(nak.packet.your_addr,&your_addr.s_addr,4);
		//memcpy(nak.packet.server_addr,&server_addr.s_addr,4);
		strcpy(MsegType,"350106");
		HexStrToByte(MsegType,nak.MsegType,6);
		HexStrToByte(server_identifier,nak.server_identifier,12);
		nak.End = 0xff;
		anack = 1;
		dhcpClntAddr.sin_addr.s_addr = inet_addr(inet_ntoa(* (struct in_addr *)(offer.packet.your_addr)));

		}

	}

	memset(Buffer,0,sizeof(Buffer));
	if(anack == 0)
	{
		memcpy(Buffer,&ack,sizeof(ack));
	}
	else
	{
		memcpy(Buffer,&nak,sizeof(nak));
	}
	
	
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpClntAddr,sizeof(dhcpClntAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}

	}

	//inform
	if(recvpacket.MesgType[2] == 0x08)
	{
		/*inform*/
		memset(&inform,0,sizeof(inform));
		memset(&inform_ack,0,sizeof(inform_ack));
		memcpy(&inform,Buffer,sizeof(inform));
		/*inform_ack*/
		
		memcpy(&inform_ack.packet,Buffer,240);
		memset(Buffer,0,sizeof(Buffer));
		inform_ack.packet.op = 0x02;
		memcpy(inform_ack.packet.your_addr,inform.packet.clint_addr,4);
		strcpy(MsegType,"350105");
		HexStrToByte(MsegType,inform_ack.MsegType,6);
		HexStrToByte(server_identifier,inform_ack.server_identifier,12);
		HexStrToByte(subnetmask,inform_ack.subnetmask,12);
	
		HexStrToByte(router,inform_ack.router,12);
	
		//HexStrToByte(domain_name,inform_ack.domain_name,20);
		inform_ack.End = 0xff;

		memcpy(Buffer,&inform_ack,sizeof(inform_ack));
	dhcpClntAddr.sin_addr.s_addr = inet_addr(inet_ntoa(* (struct in_addr *)(inform.packet.clint_addr)));
	printf("is is is: %s\n",inet_ntoa(* (struct in_addr *)(inform.packet.clint_addr)));
	if((sendto(sock,Buffer,recvMsgSize,0,(struct sockaddr *)&dhcpClntAddr,sizeof(dhcpClntAddr))) != recvMsgSize)
	{
		printf("sendto() sent a different number of bytes than expected.\n");
	}

	}
	
	//release
	if(recvpacket.MesgType[2] == 0x07)
	{
		memset(&release,0,sizeof(release));
		memcpy(&release,Buffer,sizeof(release));
		ip[choose-1].available = 0;
		printf("which IP should release? %d",choose);
		printf("IP is released, which is: %s\n",inet_ntoa(* (struct in_addr *)(release.packet.clint_addr)));
		FILE *fd3;
		fd3=fopen("dhcp.lease","r");
		i=0;
		while(fscanf(fd3,"%s %s %d",iplease[i].ipaddr,iplease[i].clientmac,&iplease[i].lease_time)!=EOF)
		{
			i++;
		}
		fclose(fd3);
		printf("file descriper: %d\n",i);

		
		if(i == 1)
		{
			int fd4;
			int fd5;
			if((fd5 = remove("dhcp.lease")) ==0)
			{
				printf("remove success\n");
			}
			
			if((fd4=open("dhcp.lease",O_CREAT|O_RDWR|O_APPEND))==-1)
			printf("Error in opening"); 
			close(fd4);
		}
		else if(i>1)
		{
			int fd4;
			int fd5;
			if((fd5 = remove("dhcp.lease")) ==0)
			{
				printf("remove success\n");
			}
			if((fd4=open("dhcp.lease",O_CREAT|O_RDWR|O_APPEND))==-1)
			printf("Error in opening"); 
		    int j;
		    for(j=0;j<i-1;j++)
		    {
		    	char filewriter[45];
				sprintf(filewriter,"%s %s %d\n",iplease[j].ipaddr,iplease[j].clientmac,iplease[j].lease_time);
				int strlength = strlen(filewriter);
				printf("strlength is: %d\n",strlength);
				if(write(fd4,filewriter,strlength)!=strlength)
				{
					printf("filewriter write error\n");
				}
		    }
		    close(fd4);
		}
	}

}	
}
