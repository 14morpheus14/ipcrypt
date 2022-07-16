#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define ENCRYPT 0
#define DECRYPT 1
#define ROTL(X, R) (X) = (unsigned char) (((X) << (R)) & 0xff) | ((X) >> (8 - (R)))
#define ROUNDS 50000

int change_key(unsigned char *key)
{
    const char *pwd = "Password";
    if(PKCS5_PBKDF2_HMAC_SHA1(pwd, strlen(pwd), (const unsigned char*)key, sizeof(key)-1, ROUNDS, sizeof(key), key) == 0 )
      fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
    
    return 0;
}
static inline void xor4(int *out, int *x, unsigned char *y)
{
    out[0] = (x[0] ^ y[0]) & 0xff;
    out[1] = (x[1] ^ y[1]) & 0xff;
    out[2] = (x[2] ^ y[2]) & 0xff;
    out[3] = (x[3] ^ y[3]) & 0xff;
}

static void arx_bwd(int *state)
{
    ROTL(state[2], 4);    //rotl(b2,4)
    state[1] ^= state[2]; //b1 ^=b2
    state[3] ^= state[0]; //b3 ^=b0
    ROTL(state[1], 5);    //rotl(b1,5)
    ROTL(state[3], 1);    //rotl(b3,1)
    state[0] -= state[3]; //b0 -=b3
    state[2] -= state[1]; //b2 -=b1
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
    ROTL(state[0], 4);    //rotl(b0,4)
    state[1] ^= state[0]; //b1 ^=b0
    state[3] ^= state[2]; //b3 ^=b2
    ROTL(state[1], 6);    //rotl(b1,6)
    ROTL(state[3], 3);    //rotl(b3,3)
    state[0] -= state[1]; //b0 -=b1
    state[2] -= state[3]; //b2 -=b3
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
}

static void arx_fwd(int *state)
{
    state[0] += state[1]; //b0 +=b1
    state[2] += state[3]; //b2 +=b3
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b0 &=0xff
    ROTL(state[1], 2);    //rotl(b1,2)
    ROTL(state[3], 5);    //rotl(b3,5)
    state[1] ^= state[0]; //b1 ^= b0
    state[3] ^= state[2]; //b3 ^= b2
    ROTL(state[0], 4);    //rotl(b0,4)
    state[0] += state[3]; //b0 +=b3
    state[2] += state[1]; //b2 +=b1
    state[0] &= 0xff;     //b0 &=0xff
    state[2] &= 0xff;     //b2 &=0xff
    ROTL(state[1], 3);    //rotl(b1,3)
    ROTL(state[3], 7);    //rotl(b3,7)
    state[1] ^= state[2]; //b1 ^=b2
    state[3] ^= state[0]; //b3 ^=b0
    ROTL(state[2], 4);    //rotl(b2,4)
}


unsigned char *ip4crypt(char *ip, unsigned char *key, int dir)
{
    int state[4];
    int in[4] = {0,0,0,0};
    int out[4] = {0,0,0,0};
    unsigned char *output = (char*) malloc(sizeof(ip));
    if (4 == sscanf(ip,"%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]", &in[0], &in[1], &in[2], &in[3]))
    {
        if(!dir){
            xor4(state, in, key);
            arx_fwd(state);
            xor4(state, state, key + 4);
            arx_fwd(state);
            xor4(state, state, key + 8);
            arx_fwd(state);
            xor4(out, state, key + 12);
        }
        else
        {
            xor4(state, in, key + 12);
            arx_bwd(state);
            xor4(state, state, key + 8);
            arx_bwd(state);
            xor4(state, state, key + 4);
            arx_bwd(state);
            xor4(out, state, key);
        }
    }
    sprintf(output, "%d.%d.%d.%d", out[0], out[1], out[2], out[3]);
    return output;
}

int main(void)
{
  unsigned char key[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
  char *ip_enc;
  char *ip_dec = "192.168.2.1";
  
  for(int i = 0; i<5; i++)
  { 
    printf("--------------------------------------------------------------------\n\n");
    printf("KEY = %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
    
    printf("IPV4_INPUT = %s\n", ip_dec);
    
    ip_enc = ip4crypt(ip_dec, key, ENCRYPT);
    printf("IPV4_ENCRYPTED = %s\n", ip_enc);
    
    ip_dec = ip4crypt(ip_enc, key, DECRYPT);
    printf("IPV4_DECRYPTED = %s\n", ip_dec);
    
    if (change_key(key) !=0)
      fprintf(stderr, "KEY_CHANGE FAILED\n");
  }
  printf("--------------------------------------------------------------------");
  return 0;
}
