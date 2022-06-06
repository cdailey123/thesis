#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#define CRYPTO_ABYTES 8
#define CRYPTO_NOOVERLAP 1
#define CRYPTO_BYTES 64

#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*8
