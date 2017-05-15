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


/*compile:
cd /home/xuyi/Desktop/
gcc ibecli.c -o ibecli -I /usr/local/include/pbc/  -lcrypto

run:

./ibecli 192.168.45.144
*/
  

#define MAXLINE 4096



int main(int argc, char** argv)  
{  
	if( argc != 2)
	{  
	    printf("usage: ./cli <ipaddress>\n");  
	    exit(0);  
    }  
  
	int sockfd, n, rec_len;  
    char recvline[4096], sendline[4096]; 
	char key[4096]; 
    char buf[MAXLINE];  
    struct sockaddr_in servaddr;
    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{  
	    printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);  
	    exit(0);  
    }
	int option=1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));//reused immediately.  
	
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<get MAC addr of current socket
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
        else { exit(-2); }
    }
    unsigned char mac_addr[6];
    if (success) memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	//printf("80 MAC of the socket is:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>get MAC addr of current socket

    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons(8000);  
    if( inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
	{  
	    printf("inet_pton error for %s\n",argv[1]);  
	    exit(0);  
    }  
  
  
    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{  
	    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);  
	    exit(0);  
    }  
  	

//-----------------------------------------get AES key
	int keylength=128;//16 bytes
    unsigned char aes_key[keylength/8];
	int fd,fp;
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
	/* init vector */
    unsigned char iv_enc[1+AES_BLOCK_SIZE], iv_dec[1+AES_BLOCK_SIZE], iv_backup[1+AES_BLOCK_SIZE];
    //RAND_bytes(iv_enc, AES_BLOCK_SIZE);
	
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
	memcpy(iv_backup, iv_enc, AES_BLOCK_SIZE);
	close(fd);
	close(fp);
	
	
	//printf("130 len=%ld,iv_enc is:%s\n", strlen(iv_enc),iv_enc);
	//printf("131 AES_BLOCK_SIZE IS:%d\n", AES_BLOCK_SIZE);
    
    //iv_enc[AES_BLOCK_SIZE]='\0';
	
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
    //strcpy(iv_dec,iv_enc);
	//iv_dec[AES_BLOCK_SIZE]='\0';
	
	//printf("142 len=%ld,iv_enc is:%s\n", strlen(iv_enc),iv_enc);
	//printf("143 len=%ld,iv_dec is:%s\n", strlen(iv_dec),iv_dec);
	
	AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_set_decrypt_key(aes_key, keylength, &dec_key);
//-----------------------------------------get AES key

	
	
//-----------------------------------------------------------------TLS standard data strcture
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
//-----------------------------------------------------------------	TLS standard data strcture


//---------------------------------------encrypt before send
	char *aes_input="HELLO";
	//aes_input=(char*)malloc(sizeof(char)*n);
	//printf("Please input plaintext:\n");
	//scanf("%[^\n]s",aes_input);
	//getchar();
	size_t inputslength;
	inputslength = strlen(aes_input);
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    memset(enc_out, 0, sizeof(enc_out));
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
	enc_out[encslength]='\0';
	//printf("165 len=%ld %ld, enc_out is:%s\n", strlen(enc_out), encslength, enc_out);
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
		exit(0);  
	}

	//printf("len=%ld send ok.\n",encslength);//strlen(enc_out)
	

	



	if((rec_len = recv(sockfd, buf, MAXLINE,0)) == -1) 
	{  
		perror("recv error");  
		exit(1);  
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





