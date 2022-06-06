// Your First C++ Program
#include <cstring>
#include <chrono>
//#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

//#include "third-party/google-benchmark/include/benchmark/benchmark.h"
#include "cryptocontext.h"
#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "utils/debug.h"
#include "palisade.h"

#include "tiny/api.h"
//#include "tiny/crypto_aead.h"

#define PRINT 1
#define TINY 1

void test_BFV(unsigned char lwcipher[], unsigned char lwkey[]);
void test_BGV(unsigned char lwcipher[], unsigned char lwkey[]);
CryptoContext<DCRTPoly> GenerateBFVrnsContext(usint ptm, unsigned int adepth, unsigned int mdepth);
CryptoContext<DCRTPoly> GenerateBGVrnsContext(usint ptm, unsigned int adepth, unsigned int mdepth);
void string2hexString(unsigned char* input, int clen, char* output);
void hextobyte(char *hexstring, unsigned char* bytearray );
string convertToString(char* a, int size);
std::vector<int64_t> convertToVector(char* a, int size);

// Global Variables to compare performance
SecurityLevel securityLevel = HEStd_128_classic;
double sigma = 3.19;
usint ptm = 536903681;

/* TinyJAMBU Code */
#ifdef TINY
/*optimized state update function*/    
void state_update(unsigned int *state, const unsigned char *key, unsigned int number_of_steps)
{
        unsigned int i;
        unsigned int t1, t2, t3, t4;

        //in each iteration, we compute 128 rounds of the state update function. 
        for (i = 0; i < number_of_steps; i = i + 128)
        {
                t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
                t2 = (state[2] >> 6)  | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
                t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
                t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
                state[0] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[0]; 
        
                t1 = (state[2] >> 15) | (state[3] << 17);   
                t2 = (state[3] >> 6)  | (state[0] << 26);   
                t3 = (state[3] >> 21) | (state[0] << 11);        
                t4 = (state[3] >> 27) | (state[0] << 5);    
                state[1] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[1];

                t1 = (state[3] >> 15) | (state[0] << 17);
                t2 = (state[0] >> 6)  | (state[1] << 26);
                t3 = (state[0] >> 21) | (state[1] << 11);
                t4 = (state[0] >> 27) | (state[1] << 5);
                state[2] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[2];  

                t1 = (state[0] >> 15) | (state[1] << 17);
                t2 = (state[1] >> 6)  | (state[2] << 26);
                t3 = (state[1] >> 21) | (state[2] << 11);
                t4 = (state[1] >> 27) | (state[2] << 5);
                state[3] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[3];
        }
}
  
// The initialization  
/* The input to initialization is the 128-bit key; 96-bit IV;*/
void initialization(const unsigned char *key, const unsigned char *iv, unsigned int *state)
{
        int i;

        //initialize the state as 0  
        for (i = 0; i < 4; i++) state[i] = 0;     

        //update the state with the key  
        state_update(state, key, NROUND2);  

        //introduce IV into the state  
        for (i = 0;  i < 3; i++)  
        {
                state[1] ^= FrameBitsIV;   
                state_update(state, key, NROUND1); 
                state[3] ^= ((unsigned int*)iv)[i]; 
        }   
}

//process the associated data   
void process_ad(const unsigned char *k, const unsigned char *ad, unsigned long long adlen, unsigned int *state)
{
        unsigned long long i; 
        unsigned int j; 

        for (i = 0; i < (adlen >> 2); i++)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                state[3] ^= ((unsigned int*)ad)[i];
        }

        // if adlen is not a multiple of 4, we process the remaining bytes
        if ((adlen & 3) > 0)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
                state[1] ^= adlen & 3;
        }   
}     

//encrypt plaintext   
int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
        unsigned long long i;
        unsigned int j;
        unsigned char mac[8];
        unsigned int state[4];

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the plaintext    
        for (i = 0; i < (mlen >> 2); i++)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                state[3] ^= ((unsigned int*)m)[i];
                ((unsigned int*)c)[i] = state[2] ^ ((unsigned int*)m)[i];
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((mlen & 3) > 0)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                for (j = 0; j < (mlen & 3); j++)
                {
                        ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                        c[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(i << 2) + j];
                }
                state[1] ^= mlen & 3;
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((unsigned int*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);
        ((unsigned int*)mac)[1] = state[2];

        *clen = mlen + 8;
        for (j = 0; j < 8; j++) c[mlen+j] = mac[j];  

        return 0;
}

//decrypt a message
int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
        unsigned long long i;
        unsigned int j, check = 0;
        unsigned char mac[8];
        unsigned int state[4];

        *mlen = clen - 8;

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the ciphertext    
        for (i = 0; i < (*mlen >> 2); i++)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                ((unsigned int*)m)[i] = state[2] ^ ((unsigned int*)c)[i];
                state[3] ^= ((unsigned int*)m)[i];
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((*mlen & 3) > 0)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                for (j = 0; j < (*mlen & 3); j++)
                {
                        m[(i << 2) + j] = c[(i << 2) + j] ^ ((unsigned char*)state)[8 + j];
                        ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                }
                state[1] ^= *mlen & 3;
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((unsigned int*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);
        ((unsigned int*)mac)[1] = state[2];

        //verification of the authentication tag   
        for (j = 0; j < 8; j++) { check |= (mac[j] ^ c[clen - 8 + j]); }
        if (check == 0) return 0;
        else return -1;
}
#endif
/* TinyJAMBU Code */

void test_BFV(unsigned char *lwcipher, unsigned long long clen, unsigned char *lwkey){

  unsigned int mdepth  = 3;
  unsigned int adepth = 0;
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm, adepth, mdepth);

  char lwct[CRYPTO_BYTES]="";
  char lwckey[2*CRYPTO_KEYBYTES+1]="";
  
  string2hexString(lwcipher, clen, lwct);
  string2hexString(lwkey, 2*CRYPTO_KEYBYTES, lwckey);
  printf("Before HE Encrypt: Ciphertext - %s, Key - %s\n", lwct, lwckey);
  
 
  std::vector<int64_t> key_vect;
  std::vector<int64_t> ct_vect = convertToVector(lwct, sizeof(lwct)/sizeof(char));
  std::string keyStr = convertToString(lwckey, sizeof(lwckey)/sizeof(char));
  //lbcrypto::Ciphertext<lbcrypto::DCRTPoly> Encrypt(const lbcrypto::LPPrivateKey<lbcrypto::DCRTPoly> privateKey, lbcrypto::Plaintext plaintext) const
  //inline lbcrypto::Plaintext lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::MakePackedPlaintext(const std::vector<int64_t> &value) const
  Plaintext he_pt = cc->MakePackedPlaintext(ct_vect);
  cc->Encrypt(cc->GetPrivateKey() , he_pt);

}

void test_BGV(unsigned char lwcipher[], unsigned char lwkey[]){


    unsigned int mdepth  = 3;
    unsigned int adepth = 0;
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm, adepth, mdepth);
}

int main() {

    unsigned long long mlen = 0;
    unsigned long long clen = 0;

    unsigned char lwplaintext[CRYPTO_BYTES] = "hello";
    unsigned char lwcipher[CRYPTO_BYTES] =""; 
    unsigned char lwnpub[CRYPTO_NPUBBYTES]="";
    unsigned char lwad[CRYPTO_ABYTES]="";
    unsigned char lwnsec[CRYPTO_ABYTES]="";
    
    unsigned char lwkey[CRYPTO_KEYBYTES];

    char pl[CRYPTO_BYTES]="hello";
    char chex[CRYPTO_BYTES]="";
    char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
    char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
    char add[CRYPTO_ABYTES]="";

    for(int i = 0; i < strlen(pl); i++){
      lwplaintext[i] = pl[i];
    }
    for(int i = 0; i < strlen(pl); i++){
      lwad[i] = add[i];
    }
    //strcpy(lwplaintext,pl);
    //strcpy(lwad,add);
    hextobyte(keyhex,lwkey);
    hextobyte(nonce,lwnpub);

    printf("Plaintext: %s\n",lwplaintext);
    printf("Key: %s\n",keyhex);
    printf("Nonce: %s\n",nonce);
    printf("Additional Information: %s\n",lwad);

    int ret = crypto_aead_encrypt(lwcipher, &clen, lwplaintext, strlen(pl), lwad,
                                  strlen(add), lwnsec, lwnpub, lwkey);

    printf("Ret: %d, Mlen: %llu\n", ret, mlen);
    string2hexString(lwcipher,clen,chex);
    printf("Ciphertext: %s\n", chex);

    unsigned char *ct = lwcipher;
    unsigned char *k = lwkey;
    //printf("Ciphertext: %s\n", *ct);
    test_BFV(ct, clen, k);
    //test_BGV(lwcipher, lwkey);

    return 0;
}

/*
 * Context setup utility methods
 */
CryptoContext<DCRTPoly> GenerateBFVrnsContext(usint ptm, unsigned int adepth, unsigned int mdepth) {
  double sigma = 3.19;
  SecurityLevel securityLevel = HEStd_128_classic;
  usint dcrtBits = 60;
  usint relinWindow = 0;

  // Set Crypto Parameters
  CryptoContext<DCRTPoly> cc =
      lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::genCryptoContextBFVrns(
          ptm, securityLevel, sigma, adepth, mdepth, 0, OPTIMIZED, 2,
          relinWindow, dcrtBits);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

#if PRINT
  std::cout << "\nParameters BFVrns for depth " << mdepth << std::endl;
  std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() <<
  std::endl; std::cout << "n = " <<
  cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 <<
  std::endl; std::cout << "log2 q = " <<
  log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
  << "\n" << std::endl;
#endif

  return cc;
}

CryptoContext<DCRTPoly> GenerateBGVrnsContext(usint ptm, unsigned int adepth, unsigned int mdepth) { 

  // Get BGVrns crypto context and generate encryption keys.
  auto cc = lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::genCryptoContextBGVrns(
      mdepth, ptm, securityLevel, sigma, 2, OPTIMIZED, BV);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

#if PRINT
  std::cout << "\nParameters BGVrns for depth " << mdepth << std::endl;
  std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() <<
  std::endl; std::cout << "n = " <<
  cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 <<
  std::endl; std::cout << "log2 q = " <<
  log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
  << "\n" << std::endl;
#endif

  return cc;
}

void string2hexString(unsigned char* input, int clen, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    for (i=0;i<clen;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

void hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02hhx", &bytearray[i]);
    }
}

string convertToString(char* a, int size)
{
    int i;
    string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}

std::vector<int64_t> convertToVector(char* a, int size){
    int i;
    std::vector<int64_t> val = {};
    printf("%d\n", size);
    for (i = 0; i < size; i++) {
        val.push_back(a[i]);
        printf("%ld, ", val.back());
    }
    printf("\n");
    return val;

}
