#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<errno.h>
#include<sys/types.h> 
#include<fcntl.h> // for open
#include<unistd.h> // for close 
#include<sys/socket.h>  
#include<netinet/in.h>
#include<openssl/aes.h>//-lcrypto
#include<openssl/rand.h>
#include<sys/stat.h>
#include<sys/ioctl.h>
#include<net/if.h> 
#include<arpa/inet.h>
#include<sys/time.h>

/*compile:
cd /home/xuyi/Desktop/
gcc ibecli.c -o ibecli -I /usr/local/include/pbc/  -lcrypto

run:

./ibecli 192.168.45.144
*/
  

#define MAXLINE 4096

int    time_substract(struct timeval *result, struct timeval *begin,struct timeval *end)

{

    if(begin->tv_sec > end->tv_sec)    return -1;
    if((begin->tv_sec == end->tv_sec) && (begin->tv_usec > end->tv_usec))    return -2;
    result->tv_sec    = (end->tv_sec - begin->tv_sec);
    result->tv_usec    = (end->tv_usec - begin->tv_usec);
    if(result->tv_usec < 0)
    {
        result->tv_sec--;
        result->tv_usec += 1000000;
    }
    return 0;
}


int main(int argc, char** argv)
{  
	if( argc != 2)
	{
	    printf("usage: ./cli serverIPaddress\n");//cmd: ./cli 192.168.1.1
	    exit(-1);
    }

	int sockfd, n, rec_len;
    char recvline[4096], sendline[4096];
	char key[4096];
    char buf[MAXLINE];
    struct sockaddr_in servaddr;
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{  
	    printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);  
	    exit(-2);  
    }
    
	int option=1;
	//set the option to reused immediately. 
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)); 
	
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<get MAC addr of local side for current socket
	struct ifreq ifr;
	struct ifconf ifc;
	char ifbuf[1024];
	int success=0;
	ifc.ifc_len = sizeof(ifbuf);
	ifc.ifc_buf=ifbuf;
	if(ioctl(sockfd, SIOCGIFCONF, &ifc)==-1) {exit(1);}
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));  
	for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { exit(-3); }
    }
    unsigned char mac_addr[6];
    if (success) memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	//printf("94 MAC of the socket is:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>get MAC addr of local side for current socket

    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(8000);//server port set 8000 as default  
    if( inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
	{  
	    printf("inet_pton error for %s\n",argv[1]);  
	    exit(-4);  
    }  
  
  
    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{  
	    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);  
	    exit(-5);  
    }
  	
	//printf("99 connect ok.\n");
//-----------------------------------------read 128 bytes AES key from file
	int keylength=128;//16 bytes
    unsigned char aes_key[keylength/8];
	int fd,fp;
	if( (fd=open("key.txt", O_RDONLY | S_IROTH))==-1 )
	{
		printf("error fopen.\n");
		return -6;
	}
	if((n=read(fd, aes_key, keylength/8))!=keylength/8)
	{
		printf("read key file error!\n");
		return -7;
	}
	
	
//-----------------------------------------read 16 bytes AES init vector from file	
	/* init vector */
    unsigned char iv_enc[1+AES_BLOCK_SIZE], iv_dec[1+AES_BLOCK_SIZE], iv_backup[1+AES_BLOCK_SIZE];
    //RAND_bytes(iv_enc, AES_BLOCK_SIZE);
	
	if( (fp=open("iv.txt", O_RDONLY | S_IROTH))==-1 )
	{
		printf("error fopen.\n");
		return -8;
	}
	if((n=read(fp, iv_enc, AES_BLOCK_SIZE))!=AES_BLOCK_SIZE)
	{
		printf("read key file error!\n");
		return -9;
	}
	memcpy(iv_backup, iv_enc, AES_BLOCK_SIZE);
	close(fd);
	close(fp);
	
	
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
	
	AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_set_decrypt_key(aes_key, keylength, &dec_key);
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>get AES key

	
	
//-----------------------------------------------------------------TLS standard data strcture
	/*
	struct u48{unsigned int x32; unsigned short x16;};
	struct {
		short client_version;//2 byte  0x0301
		char random[32];//32 byte 
		int session_id;//4 byte
		short cipher_suites;//2 byte
		char compression_methods;//1 byte
		struct u48 extensions;//6 byte store MAC address
	} ClientHello;

	struct {
		short server_version;
		char random[32];
		int session_id;
		short cipher_suite;
		char compression_method;
		struct u48 extensions;
	} ServerHello;

	struct {
		enum { change_cipher_spec(1), (255) } type;
	} ChangeCipherSpec;

	struct {
		opaque verify_data[verify_data_length];
	} Finished;
	*/
//-----------------------------------------------------------------	TLS standard data strcture



//       Cli                                 Ser
// [CliHELLO+MacAddress]   --------->     
//                         <---------       [Req]
//   [HELLO+Answer]        --------->
//                         <---------  [SerHELLO+MacAddress]          
//                         <---------  [ChangeCipherSpec]
//                         <---------     [Finished]
//   [ChangeCipherSpec]    ---------> 
//     [Finished]          ---------> 

//      CipherText         <-------->    CipherText

	
	
	struct ClientHello
	{
		char TYPE;//1
		int cookie;
		char macadd[18];
	};
	
	
	struct HelloVerify
	{
		char TYPE;//2
		int cookie;
	};
	
	struct ServerHello
	{
		char TYPE;//3
		int cookie;
		char macadd[18];
	};
	
	
	struct ClientHello info1;
	struct HelloVerify info2;
	struct ServerHello info3;
	
	struct timeval start,stop,diff;
    memset(&start,0,sizeof(struct timeval));
    memset(&stop,0,sizeof(struct timeval));
    memset(&diff,0,sizeof(struct timeval));
	
	char sendbuf[4096];
	char recvbuf[4096];
	
	gettimeofday(&start,0);
	
	
	info1.TYPE='1';
	info1.cookie=-1;//-1 stand for NULL
	sprintf(info1.macadd, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	if( send(sockfd, (char*)&info1, sizeof(info1), 0) < 0)  
	{  
		printf("send error.\n");
		exit(-10);  
	}

	
	while(1)
	{
	
		if( recv(sockfd, recvbuf, 4096, 0) ==-1)
		{
			printf("recv error.\n");
			exit(-16);
		}
		
		if(recvbuf[0]=='2')//HelloVerify, return a ClientHello with cookie.
		{
			memcpy(&info2, recvbuf, sizeof(info2));
			memset(&info1, 0, sizeof(info1));
			info1.TYPE='1';
			//printf("TYPE is:%c\n", info1.TYPE);
			info1.cookie=info2.cookie;
			sprintf(info1.macadd, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
			//memcpy(sendbuf, &info1, sizeof(info1)); 
			if( send(sockfd, (char*)&info1, sizeof(info1), 0) < 0)  
			{  
				printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);  
				exit(-10);  
			}	
		}//if 
		
		else if(recvbuf[0]=='3')//ServerHello, verify success.
		{
			char sermac[20];
			memcpy(&info3, recvbuf, sizeof(info3));
			
			gettimeofday(&stop,0);
			time_substract(&diff,&start,&stop);
			
			//printf("ser mac is:%s\n", info3.macadd);
			printf("HelloVerify success!\n");
			printf("Total time : %d s,%d us\n",(int)diff.tv_sec,(int)diff.tv_usec);
			return 0;
		}
	}



	return 0;






















//---------------------------------------encrypt before send
	char *aes_input="HELLO";

	size_t inputslength;
	inputslength = strlen(aes_input);
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    memset(enc_out, 0, sizeof(enc_out));
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
	enc_out[encslength]='\0';
//---------------------------------------encrypt before send

	memcpy(iv_dec, iv_backup, AES_BLOCK_SIZE);
	memcpy(iv_enc, iv_backup, AES_BLOCK_SIZE);//iv_backup
/*-----------------------decrypt at local
	unsigned char testout[MAXLINE];
	memset(testout, 0, sizeof(testout));
	AES_cbc_encrypt(enc_out, testout, encslength, &dec_key, iv_dec, AES_DECRYPT);
	printf("175 local dec out is:%s\n", testout);
//-----------------------decrypt at local*/

	
	if( send(sockfd, enc_out, encslength, 0) < 0)  
	{  
		printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);  
		exit(-10);  
	}

	//printf("len=%ld send ok.\n",encslength);//strlen(enc_out)
	

	



	if((rec_len = recv(sockfd, buf, MAXLINE,0)) == -1) 
	{  
		perror("recv error");  
		exit(-11);  
	}
	//printf("195 before decryt is:%s\n", buf);
//--------------------------------------------------decrypt after recv
	memcpy(iv_dec, iv_backup, AES_BLOCK_SIZE);
	memcpy(iv_enc, iv_backup, AES_BLOCK_SIZE);//iv_backup
	unsigned char dec_out[MAXLINE];//[rec_len];
	memset(dec_out, 0, sizeof(dec_out));
	//AES_KEY dec_key;
    //AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(buf, dec_out, rec_len, &dec_key, iv_dec, AES_DECRYPT);
	//dec_out[rec_len]  = '\0';  
	printf("205 after decrypt, recv is:%s\n",dec_out);
//--------------------------------------------------decrypt after recv


	close(sockfd);  
    return 0;  
}  





