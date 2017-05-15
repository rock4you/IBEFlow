/*

0.pkg send the private key to each user
	a.user calculate the public key: Qa=H(MACa), Qb=H(MACb) of them selves
	b.user calculate the private key: Sa=s*Qa Sb=s*Qb, (Sa Sb is saved in local file receved form pkg)
	c.user calculate the pairing Ka=e(Sa,Qb),Kb=e(Qa,Sb) 

1.use IBE to set up secure channel.
	a.cli calculate the ecc key
	b.cli connect the ser
	c.cli encrypt the "Hello" packet to ser
	d.ser decrypt the first packet, if is "Hello" go on; else close.

2.use key K and AES-CBC to encrypt message.
*/

/*
gcc ibeser.c -o ibeser -lcrypto
./ibeser

*/
// sudo netstat -lntp


#include<stdio.h>  
#include<stdlib.h>  
#include<string.h>  
#include<errno.h>  
#include<sys/types.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/socket.h>  
#include<netinet/in.h>
#include<openssl/aes.h>//-lcrypto
#include<openssl/rand.h>
#include<sys/stat.h>
#include<sys/ioctl.h>
#include<net/if.h> 
#include<arpa/inet.h>
   
#define DEFAULT_PORT 8000
#define MAXLINE 4096


int IBErecv(char *key, int fd, char *buf, int len, int flag)
{
	int n;
	n = recv(fd, buf, len, flag);	
	//decrypt
	//decrype(buf)	
	return 0;
}

int IBESend(char *key, int fd, char *buf, int len, int flag)
{
	
	//encrypt
	//encrypt(buf)

	if(send(fd, buf, len, flag) == -1)  
	{
		//close(connect_fd);
		//close(socket_fd);
		exit(-16);
	} 
	 	
	
	return 0;
}









int main()
{
	int socket_fd, connect_fd;  
    struct sockaddr_in servaddr;  
    char buff[4096];
    int key[4096];
    int n, i, rec_len; 
    if( (socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
	{  
		printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);  
		exit(-11);  
    }
	int option=1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));//reused immediately.    
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(DEFAULT_PORT);  
    if( bind(socket_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1)
    {  
		printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);  
		exit(-12);  
	}   
    if( listen(socket_fd, 10) == -1)
    {  
		printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);  
		exit(-13);  
    }
	
	
	//----------------------------------------------------------------get MAC addr of current socket
	struct ifreq ifr;
	struct ifconf ifc;
	char ifbuf[1024];
	int success=0;
	ifc.ifc_len = sizeof(ifbuf);
	ifc.ifc_buf=ifbuf;
	if(ioctl(socket_fd, SIOCGIFCONF, &ifc)==-1) {exit(1);}
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));  
	for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(socket_fd, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(socket_fd, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { exit(-2); }
    }
    unsigned char mac_addr[6];
    if (success) memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	
	//printf("134 MAC of the socket is:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
//----------------------------------------------------------------get MAC addr of current socket


    //printf("======waiting for client's request======\n");  
    



	while(1)
	{
    	//阻塞直到有客户端连接
		if( (connect_fd = accept(socket_fd, (struct sockaddr*)NULL, NULL)) == -1)
		{  
			printf("accept socket error: %s(errno: %d)",strerror(errno),errno);  
			continue;  
	   	}
	   	else
	   		break;  
	}

	
	

	//-------------------------------------------------------------------------get AES key form file
	int keylength=128;//16 bytes
    unsigned char aes_key[keylength/8];
	int fd, fp;
	if( (fd=open("key.txt", O_RDONLY | S_IROTH))==-1 )
	{
		printf("error fopen.\n");
		return -1;
	}
	if((n=read(fd, aes_key, keylength/8))!=keylength/8)
	{
		printf("read key file error!\n");
		return -2;
	}
	close(fd);
	AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_set_decrypt_key(aes_key, keylength, &dec_key);
	//-------------------------------------------------------------------------get AES key form file
	

	//------------------------------------------ init vector from file 
    unsigned char iv_enc[1+AES_BLOCK_SIZE], iv_dec[1+AES_BLOCK_SIZE], iv_backup[1+AES_BLOCK_SIZE];
	if( (fp=open("iv.txt", O_RDONLY | S_IROTH))==-1 )
	{
		printf("error fopen.\n");
		return -1;
	}
	if((n=read(fp, iv_enc, AES_BLOCK_SIZE))!=AES_BLOCK_SIZE)
	{
		printf("read key file error!\n");
		return -2;
	}
	close(fp);
	memcpy(iv_backup, iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
	//printf("189 len=%ld,iv_enc is:%s\n", strlen(iv_enc),iv_enc);
	//printf("190 len=%ld,iv_dec is:%s\n", strlen(iv_dec),iv_dec);
	//------------------------------------------ init vector from file 
	

	memset(buff, 0, sizeof(buff));
	//The first packet from client.	
	if(( rec_len = recv(connect_fd, buff, MAXLINE, 0))==-1) 
	{
		printf("recv error.\n");
		exit(-16);
	}
	//printf("len=%ld, before decryt is:%s\n", strlen(buff), buff);
	




	//-------------------------------------------------------------------------decrypt after recv
	unsigned char dec_out[MAXLINE];//inputslength != encslength.
	memset(dec_out, 0, sizeof(dec_out));
    AES_cbc_encrypt(buff, dec_out, 16, &dec_key, iv_dec, AES_DECRYPT);

	//dec_out[rec_len]  = '\0';  
	printf("210after decrypt, recv is:%s\n",dec_out);
	memcpy(iv_dec, iv_backup, AES_BLOCK_SIZE);
	memcpy(iv_enc, iv_backup, AES_BLOCK_SIZE);//iv_backup
	//-------------------------------------------------------------------------decrypt after recv





	
	//---------------------------------------encrypt before send
	char *aes_input="HELLO";
	//aes_input=(char*)malloc(sizeof(char)*n);
	//printf("Please input plaintext:\n");
	//scanf("%[^\n]s",aes_input);
	//getchar();
	size_t inputslength;
	inputslength = strlen(aes_input);
	// buffers for encryption and decryption
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    memset(enc_out, 0, sizeof(enc_out));
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
	enc_out[encslength]='\0';
	//printf("223 len=%ld %ld, enc_out is:%s\n", strlen(enc_out), encslength, enc_out);
	memcpy(iv_dec, iv_backup, AES_BLOCK_SIZE);
	memcpy(iv_enc, iv_backup, AES_BLOCK_SIZE);//iv_backup
	
	
	//---------------------------------------encrypt before send
	
	
	/*-----------------------decrypt it self
	unsigned char testout[MAXLINE];
	memset(testout, 0, sizeof(testout));
	AES_cbc_encrypt(enc_out, testout, encslength, &dec_key, iv_dec, AES_DECRYPT);
	printf("235 local dec out is:%s\n", testout);
	memcpy(iv_dec, iv_backup, AES_BLOCK_SIZE);
	memcpy(iv_enc, iv_backup, AES_BLOCK_SIZE);//iv_backup
	//-----------------------decrypt it self*/
	
	
	if((send(connect_fd, enc_out, encslength, 0))==-1)
	{
		close(connect_fd);
		close(socket_fd);
		exit(-15);
	}
	close(connect_fd);
    close(socket_fd);
	
}
