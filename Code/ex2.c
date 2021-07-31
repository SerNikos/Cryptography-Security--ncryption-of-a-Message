//NIKOLAOS SERGIS PADA EX_2

#include <stdio.h> //basic library for input/output 
#include <openssl/bn.h> //library that helps the computer to deal with big numbers and not cause overflow
#define NBITS 128 //constant for bn, (in real life problems that number would be at least 512 bits)

//Function that prints a bn number
void printBN(char *msg, BIGNUM * a)
{

 /* Use BN_bn2hex(a) for hex string
 * Use BN_bn2dec(a) for decimal string */
 char * number_str = BN_bn2hex(a);
 printf("%s %s\n", msg, number_str);
 OPENSSL_free(number_str);

}

int main ()
{

//Varables declaration
 BN_CTX *ctx = BN_CTX_new(); //a temporary struct to help with the computational process of large numbers
 BIGNUM *p = BN_new(); //a first number
 BIGNUM *q = BN_new(); //a first number
 BIGNUM *e = BN_new(); //public key
 BIGNUM *n = BN_new(); //n will is the result of the multiplication of two first numbers p*q
 BIGNUM *d = BN_new(); //private key
 BIGNUM *M = BN_new(); //message
 BIGNUM *rese = BN_new(); //this varable will be used in the encryption proccess
 BIGNUM *resd = BN_new(); //this varable will be used in the decryption proccess

//initialize p, q, e, n, d and M
 BN_hex2bn(&p, "953AAB9B3F23ED593FBDC690CA10E703");
 BN_hex2bn(&q, "C34EFC7C4C2369164E953553CDF94945");
 BN_hex2bn(&e, "0D88C3");
 BN_hex2bn(&n, "71D9BBC5C01F9B50DDFE5F2EC331FAB21081009D014E9615C277670C61591ECF");
 BN_hex2bn(&d, "63F67E805D8DEB0B4182C57C3DC24F3C1350CF182E8ABF85FD24062A3BC7F2EB");
 
//Declaration of my surname
 BN_hex2bn(&M, "4e494b4f4c414f5320534552474953"); 
 
//Prints my surname in hex
 printBN("the message is", M);  

//Encryption of the message *NIKOLAOS SERGIS*
 BN_mod_exp(rese,M,e,n,ctx); // Message^e mod n
 
//Prints the encrypted message
 printBN("the encrypted message is ", rese);

//Decryption of the message
 BN_mod_exp(resd,rese,d,n,ctx); // Encrypted_Message^d mod n
  
//Prints the decrypted message
 printBN("the decrypted message is ", resd); 

return 0;

}
