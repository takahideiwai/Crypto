---
title: "RSA Public-Key Encryption and Signature Lab/Answers"
teaching: 30
exercises: 60
questions:
- "What is RSA?"
- "How is RSA used in Computer security?"
- "How is RSA used to encrypt and decrypt messages?"
- "How is RSA used to sign and verify signatures?"
objectives:
- "Follow instructions to successfully encrypt and decrypt some messages, sign and verify signatures."
keypoints:
- "It is best to copy and paste the private keys, public keys, messages and so on"
- "Code can be written using vim which is available within the container"
- "An example codes can be found in the answers directory."
---
## RSA Public-Key Encryption and Signature Lab  
### Acknowledgement  
This lab was developed with the help of Shatadiya Saha, a graduate student in the Department of Electrical Engineering and Computer Science at Syracuse University.  
This lab was originally designed by [SEEDLabs](http://www.cis.syr.edu/~wedu/seed/Labs_16.04/Crypto/Crypto_RSA/) and Dr. Wenliang Du. 

> ## Warning
> Example codes are given in this instruction guide however, students are encouraged to create their own code to get the most out of this lab!!
{: .callout}

### Introduction  

RSA (RivestShamirAdleman) is one of the first public-key cryptosystems and is widely used for secure communication. The RSA algorithm first generates two large random prime numbers, and then use them to generate public and private key pairs, which can be used to do encryption, decryption, digital signature generation, and digital signature verification. The RSA algorithm is built upon number theories, and it can be quite easily implemented with the support of libraries.
The learning objective of this lab is for students to gain hands-on experiences on the RSA algorithm. From lectures, students should have learned the theoretic part of the RSA algorithm, so they know math- ematically how to generate public/private keys and how to perform encryption/decryption and signature generation/verification. This lab enhances student’s understanding of RSA by requiring them to go through every essential step of the RSA algorithm on actual numbers, so they can apply the theories learned from the class. Essentially, students will be implementing the RSA algorithm using the C program language. The lab covers the following security-related topics:
- Public-key cryptography
- The RSA algorithm and key generation
- Big number calculation
- Encryption and Decryption using RSA
- Digital signature
- X.509 certificate

### Background  

The RSA algorithm involves computations on large numbers. These computations cannot be directly con- ducted using simple arithmetic operators in programs, because those operators can only operate on primitive data types, such as 32-bit integer and 64-bit long integer types. The numbers involved in the RSA algorithms are typically more than 512 bits long. For example, to multiple two 32-bit integer numbers a and b, we just need to use a*b in our program. However, if they are big numbers, we cannot do that any more; instead, we need to use an algorithm (i.e., a function) to compute their products.
There are several libraries that can perform arithmetic operations on integers of arbitrary size. In this lab, we will use the Big Number library provided by *openssl*. To use this library, we will define each big number as a *BIGNUM* type, and then use the APIs provided by the library for various operations, such as addition, multiplication, exponentiation, modular operations, etc.
### BIGNUM APIs  

All the big number APIs can be found from https://linux.die.net/man/3/bn. In the following, we describe some of the APIs that are needed for this lab.  

- Some of the library functions requires temporary variables. Since dynamic memory allocation to cre- ate BIGNUMs is quite expensive when used in conjunction with repeated subroutine calls, a BN CTX structure is created to holds BIGNUM temporary variables used by library functions. We need to create such a structure, and pass it to the functions that requires it.  

``` c
 BN_CTX *ctx = BN_CTX_new()
```
- Initialize a BIGNUM variable  

``` c
 BIGNUM *a = BN_new()
```
- There are a number of ways to assign a value to a BIGNUM variable.  

``` c
// Assign a value from a decimal number string
BN_dec2bn(&a, "12345678901112231223");
// Assign a value from a hex number string
BN_hex2bn(&a, "2A3B4C55FF77889AED3F");
// Generate a random number of 128 bits
BN_rand(a, 128, 0, 0);
// Generate a random prime number of 128 bits
BN_generate_prime_ex(a, 128, 1, NULL, NULL, NULL);
```  
- Print out a big number. 

```c
void printBN(char *msg, BIGNUM * a)
{
// Convert the BIGNUM to number string
char * number_str = BN_bn2dec(a);
// Print out the number string
printf("%s %s\n", msg, number_str);
// Free the dynamically allocated memory
   OPENSSL_free(number_str);
}
```
- Compute *res = a−b* and *res = a+b*:  

```c
BN_sub(res, a, b);
BN_add(res, a, b);
```
- Compute *res = a ∗ b*. It should be noted that a BN CTX structure is need in this API.  

```c
BN_mul(res, a, b, ctx)
``` 
- Compute *res = a∗b* mod n:  

```c
BN_mod_mul(res, a, b, n, ctx)
```
- Compute *res = a^c mod n*:   

```c
BN_mod_exp(res, a, c, n, ctx)
```
- Compute modular inverse, i.e., given *a*, find *b*, such that *a ∗ b mod n = 1*. The value *b* is called the inverse of *a*, with respect to modular *n*.  

```c
BN_mod_inverse(b, a, n, ctx);
```
### A Complete Example
We show a complete example in the following. In this example, we initialize three BIGNUM variables, *a*, *b*,and *n*; we then compute *a∗b* and *(ab mod n)*.    


```c
/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
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
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *res = BN_new();
// Initialize a, b, n
  BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
  BN_dec2bn(&b, "273489463796838501848592769467194369268");
  BN_rand(n, NBITS, 0, 0);
// res = a*b
  BN_mul(res, a, b, ctx);
  printBN("a * b = ", res);
// res = aˆb mod n
  BN_mod_exp(res, a, b, n, ctx);
  printBN("aˆc mod n = ", res);
  return 0;
}
```

#### compilation
We can use the following command to compile bn sample.c (the character after - is the letter l, not the number 1; it tells the compiler to use the crypto library).  

~~~
$ gcc bn_sample.c -lcrypto
~~~
{: .language-bash}

### Lab Tasks
To avoid mistakes, please avoid manually typing the numbers used the lab tasks. Instead, copy and paste the numbers from this PDF file.  

### Task 1: Deriving the Private Key
Let *p*, *q*, and *e* be three prime numbers. Let *n = p∗q*. We will use *(e, n)* as the public key. Please calculate the private key d. The hexadecimal values of *p*, *q*, and *e* are listed in the following. It should be noted that although p and q used in this task are quite large numbers, they are not large enough to be secure. We intentionally make them small for the sake of simplicity. In practice, these numbers should be at least 512 bits long (the one used here are only 128 bits).  

~~~
p = F7E75FDC469067FFDC4E847C51F452DF
q = E85CED54AF57E53E092113E62F436F4F
e = 0D88C3
~~~
{: .source}  

The equations to calculate the private key *d* are listed below.  
![equation]({{ page.root }}/fig/rsa/n.png)
![equationtwo]({{ page.root }}/fig/rsa/phi.png)
![equationthree]({{ page.root }}/fig/rsa/d.png)  

The following are the example code for Task1.  
```c
/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
/*
Use BN_bn2hex(a) for hex string*
Use BN_bn2dec(a) for decimal string
*/
char *number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}



int main ()
{
//declare necessary variables
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *p_1 = BN_new();
BIGNUM *q = BN_new();
BIGNUM *q_1 = BN_new();
BIGNUM *e = BN_new();
BIGNUM *d = BN_new();
BIGNUM *n = BN_new();
BIGNUM *n_1 = BN_new();
BIGNUM *one = BN_new();

//Initialize p,q,e,one
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");
BN_dec2bn(&one,"1");

// P_1=p-1
BN_sub(p_1,p,one);

//q_1=q-1
BN_sub(q_1,q,one);

//n_1=(p-1)(q-1)
BN_mul(n_1,p_1,q_1,ctx);

//d=e^-1 mod (n-1)
BN_mod_inverse(d,e,n_1,ctx);

//printing out the value of d
printBN("d is ",d);

return 0;
}
```

Type in the following command to compile the program named task1.c.  
~~~
gcc task1.c -lcrypto
~~~
{: .language-bash}

Type in the following command to execute the program.  
~~~
./a.out
~~~
{: .language-bash}

You should get the following output.  
~~~
d is  3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
~~~
{: .output}

### Task 2: Encrypting a Message
Let *(e, n)* be the public key. Please encrypt the message "A top secret!" (the quotations are not included). We need to convert this ASCII string to a hex string, and then convert the hex string to a *BIGNUM* using the hex-to-bn API *BN_hex2bn()*. The following *python* command can be used to convert a plain ASCII string to a hex string.
~~~
 $ python2.7  -c ’print("A top secret!".encode("hex"))’
   4120746f702073656372657421
~~~
{: .language-bash}

The public keys are listed in the followings (hexadecimal). We also provide the private key *d* to help you verify your encryption result.

~~~
n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
e = 010001 (this hex value equals to decimal 65537)
M = A top secret!
d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D
~~~
{: .source}  

The equation to encrypt a message is
![enc]({{ page.root}}/fig/rsa/c.png)  
The equation to decrypt a message is  
![enc]({{ page.root}}/fig/rsa/m.png)  

The following is the example code for Task 2  and Task 3.  
```c
/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
/*
Use BN_bn2hex(a) for hex string*
Use BN_bn2dec(a) for decimal string
*/
char *number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}



int main ()
{
//declaring variables
BN_CTX *ctx = BN_CTX_new();
BIGNUM *crypt = BN_new();
BIGNUM *m = BN_new();
BIGNUM *n = BN_new();
BIGNUM *e = BN_new();
BIGNUM *d = BN_new();
BIGNUM *decrypt =BN_new();

//initializing variables 
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&e, "010001");
BN_hex2bn(&m, "4120746f702073656372657421");

//calculating c=m^e mod n
BN_mod_exp(crypt,m,e,n,ctx);

//calculating the encrypted message
printBN("The encrypted message is ", crypt);

//calculating m=c^d mod n
BN_mod_exp(decrypt,crypt,d,n,ctx);

//printing out the decrypted message 
printBN("The decrypted message is ", decrypt);
return 0;
}
```

Type in the following command to compile the program named task2.c.  
~~~
gcc task2.c -lcrypto
~~~
{: .language-bash}

Type in the following command to execute the program.  
~~~
./a.out
~~~
{: .language-bash}
~~~
The encrypted message is  6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
The decrypted message is  4120746F702073656372657421
~~~
{: .output}  

> ## Callout
>As you can see from the result above, the decrypted message '4120746F702073656372657421' is equivalent to the   
>ASCII string 'A top secret!'
{: .callout}




### Task 3: Decrypting a Message
The public/private keys used in this task are the same as the ones used in Task 2. Please decrypt the following ciphertext C, and convert it back to a plain ASCII string.

~~~
C = 8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F
~~~
{: .source}  


You can use the following python command to convert a hex string back to to a plain ASCII string.  

~~~
$ python2.7  -c ’print("4120746f702073656372657421".decode("hex"))’
A top secret!
~~~
{: .language-bash}  

The eqution and the example code to decrypt a message is given in task 2. You will need to slightly modify the code.   

Type in the following command to compile the program named task3.c.  
~~~
gcc task3.c -lcrypto
~~~
{: .language-bash}

Type in the following command to execute the program.  
~~~
./a.out
~~~
{: .language-bash}

~~~
The decrypted message is  50617373776F72642069732064656573
~~~
{: .output}

Type in the following command to convert the hexadecimal string to an ASCII string. 
~~~
python2.7 -c 'print("50617373776F72642069732064656573".decode("hex"))'
~~~
{: .language-bash}

You will get the following output.  
~~~
Password is dees
~~~
{: .output}

### Task 4: Signing a Message 
The public/private keys used in this task are the same as the ones used in Task 2. Please generate a signature for the following message (please directly sign this message, instead of signing its hash value):
~~~
 M = I owe you $2000.
~~~
{: .source}  

Please make a slight change to the message M, such as changing $2000 to $3000, and sign the modified message.   
Compare both signatures and describe what you observe.  
The equation to sign the message is   
![enc]({{ page.root}}/fig/rsa/sig.png) 
The example code is the following.  

```c
/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
/*
Use BN_bn2hex(a) for hex string*
Use BN_bn2dec(a) for decimal string
*/
char *number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}

int main ()
{
//declaring variables
BN_CTX *ctx = BN_CTX_new();
BIGNUM *m = BN_new();
BIGNUM *n = BN_new();
BIGNUM *e = BN_new();
BIGNUM *d = BN_new();
BIGNUM *ver =BN_new();
BIGNUM *sig =BN_new();

//initializing the variables
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&e, "010001");
BN_hex2bn(&m, "49206f776520796f752024333030302e");

// Signing the message by calculating sig=m^d mod n
BN_mod_exp(sig,m,d,n,ctx);
//Printing out the signed message
printBN("The signed certificate is ", sig);

// Verifying the message by calculating ver=m^d mod n
BN_mod_exp(ver,sig,e,n,ctx);

//Printing out the verified message
printBN("The verified certificate is ", ver);
return 0;
}
```   

Type in the following command to convert the ASCII string to a hexadecimal string.  
~~~
python2.7 -c 'print("I owe you $3000.".encode("hex"))'
~~~
{: .language-bash}

You will get the following output.  
~~~
49206f776520796f752024323030302e
~~~
{: .output}
Type in the following command to compile the program named task4.c.  
~~~
gcc task4.c -lcrypto
~~~
{: .language-bash}

Type in the following command to execute the program.  
~~~
./a.out
~~~
{: .language-bash}

You will get the following out put. 
~~~
The signed certificate is  BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822
The verified certificate is  49206F776520796F752024333030302E. 
~~~
{: .output} 

> ## Callout
>The verified certificate '49206F776520796F752024333030302E' is equivalent to the ASCII string 'I owe you $3000.'
{: .callout}



### Task 5: Verifying a Signature  
Bob receives a message M = "Launch a missile." from Alice, with her signature S. We know that Alice’s public key is (e, n). Please verify whether the signature is indeed Alice’s or not. The public key and signature (hexadecimal) are listed in the following: 

~~~
M = Launch a missle.
S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
e = 010001 (this hex value equals to decimal 65537)
n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
~~~
{: .source}  

The equation to verify the signed message is  
![ver]({{ page.root}}/fig/rsa/ver.png)

Suppose that the signature in is corrupted, such that the last byte of the signature changes from *2F* to *3F*, i.e, there is only one bit of change. Please repeat this task, and describe what will happen to the verification process.

Type in the following command to compile the program named task5.c.  
~~~
gcc task5.c -lcrypto
~~~
{: .language-bash}

Type in the following command to execute the program.  
~~~
./a.out
~~~
{: .language-bash}

You will get the following out put. 
~~~
The verified certificate is  4C61756E63682061206D697373696C652E
~~~
{: .output}

Type in the following command to convert the hexadecimal string to a ASCII string  
~~~
 $ python2.7  -c ’print("4C61756E63682061206D697373696C652E".encode("hex"))’
~~~
{: .language-bash}  
You will get the following hexadecimal string.  
~~~
Launch a missle.
~~~
{: .output}
Change the last two digit of the signature from 2F to 3F and repeat the steps.   
You will get the following output.
~~~
The verified certificate is  91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294
~~~
{: .output}  

> ## Warning
>The outcome should vary significantly just by slightly changing the original signed message.
{: .callout}  



### Task 6: Manually Verifying an X.509 Certificate
In this task, we will manually verify an X.509 certificate using our program. An X.509 contains data about a public key and an issuer’s signature on the data. We will download a real X.509 certificate from a web server, get its issuer’s public key, and then use this public key to verify the signature on the certificate.
#### Step 1: Download a certificate from a real web server.
We use the www.example.org server in this document. Students should choose a different web server that has a different certificate than the one used in this document (it should be noted that www.example.com share the same certificate with www.example.org). We can download certificates using browsers or use the following command:  

~~~
$ openssl s_client -connect www.example.org:443 -showcerts
Certificate chain
 0 s:/C=US/ST=California/L=Los Angeles/O=Internet Corporation for Assigned
     Names and Numbers/OU=Technology/CN=www.example.org
i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High Assurance
  Server CA
-----BEGIN CERTIFICATE-----
MIIF8jCCBNqgAwIBAgIQDmTF+8I2reFLFyrrQceMsDANBgkqhkiG9w0BAQsFADBw
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
......
wDSiIIWIWJiJGbEeIO0TIFwEVWTOnbNl/faPXpk5IRXicapqiII=
  -----END CERTIFICATE-----
1 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 High
    Assurance Server CA
  i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance
EV Root CA
-----BEGIN CERTIFICATE-----
MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
......
cPUeybQ=
-----END CERTIFICATE-----
~~~
{: .output}  

The result of the command contains two certificates. The subject field (the entry starting with s:) of the certificate is www.example.org, i.e., this is www.example.org’s certificate. The issuer field (the entry starting with i:) provides the issuer’s information. The subject field of the second certificate is the same as the issuer field of the first certificate. Basically, the second certificate belongs to an intermediate CA. In this task, we will use CA’s certificate to verify a server certificate.
If you only get one certificate back using the above command, that means the certificate you get is signed by a root CA. Search for the name of the issuer and download its certificate.
Copy and paste each of the certificate (the text between the line containing "Begin CERTIFICATE" and the line containing "END CERTIFICATE",including these two lines) to a file.Let us call the first one **c0.pem** and the second one **c1.pem**.

#### Step 2: Extract the public key (e, n) from the issuer’s certificate. 
openssl provides commands to extract certain attributes from the x509 certificates. We can extract the value of *n* using *-modulus*. There is no specific command to extract *e*, but we can print out all the fields and can easily find the value of *e*.

~~~
 For modulus (n):
$ openssl x509 -in c1.pem -noout -modulus
 Print out all the fields, find the exponent (e):
$ openssl x509 -in c1.pem -text -noout
~~~
{: .language-bash}  


#### Step 3: Extract the signature from the server’s certificate.
There is no specific openssl command to extract the signature field. However, we can print out all the fields and then copy and paste the signature block into a file (note: if the signature algorithm used in the certificate is not based on RSA, you can find another certificate).
~~~
$ openssl x509 -in c0.pem -text -noout
~~~
{: .language-bash}  

~~~
...
Signature Algorithm: sha256WithRSAEncryption
  84:a8:9a:11:a7:d8:bd:0b:26:7e:52:24:7b:b2:55:9d:ea:30:
  89:51:08:87:6f:a9:ed:10:ea:5b:3e:0b:c7:2d:47:04:4e:dd:
......
5c:04:55:64:ce:9d:b3:65:fd:f6:8f:5e:99:39:21:15:e2:71:
aa:6a:88:82
~~~
{: .output}  

We need to remove the spaces and colons from the data, so we can get a hex-string that we can feed into our program. The following command commands can achieve this goal. The tr command is a Linux utility tool for string operations. In this case, the -d option is used to delete ":" and "space" from the data.
~~~
$ cat signature | tr -d ’[:space:]:’
84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc7
......
5c045564ce9db365fdf68f5e99392115e271aa6a8882
~~~
{: .language-bash}  


#### Step 4: Extract the body of the server’s certificate.
A Certificate Authority (CA) generates the signature for a server certificate by first computing the hash of the certificate, and then sign the hash. To verify the signature, we also need to generate the hash from a certificate. Since the hash is generated before the signature is computed, we need to exclude the signature block of a certificate when computing the hash. Finding out what part of the certificate is used to generate the hash is quite challenging without a good understanding of the format of the certificate.
X.509 certificates are encoded using the ASN.1 (Abstract Syntax Notation.One) standard, so if we can parse the ASN.1 structure, we can easily extract any field from a certificate. Openssl has a command called asn1parse, which can be used to parse a X.509 certificate.  

~~~
$ openssl asn1parse -i -in c0.pem
    0:d=0  hl=4 l=1856 cons: SEQUENCE
    4:d=1  hl=4 l=1576 cons:  SEQUENCE
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  16 prim:   INTEGER           :0FD078DD48F1A2BD4D0F2BA96B6038FE

.....
 1584:d=1  hl=2 l=  13 cons:  SEQUENCE
 1586:d=2  hl=2 l=   9 prim:   OBJECT            :sha256WithRSAEncryption
 1597:d=2  hl=2 l=   0 prim:   NULL
 1599:d=1  hl=4 l= 257 prim:  BIT STRING
~~~
{: .output}  

The field starting from **4:** is the body of the certificate that is used to generate the hash; the field starting from **1586**: is the signature block. Their offsets are the numbers at the beginning of the lines. In our case, the certificate body is from offset 4 to 1585, while the signature block is from 1585 to the end of the file. For X.509 certificates, the starting offset is always the same (i.e., 4), but the end depends on the content length of a certificate. We can use the -strparse option to get the field from the offset 4, which will give us the body of the certificate, excluding the signature block.

~~~
$ openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout
~~~
{: .language-bash}

Once we get the body of the certificate, we can calculate its hash using the following command:

~~~
$ sha256sum c0_body.bin
~~~
{: .language-bash} 
You will get the following output. 
~~~
2c2a46bf245dab54ddb47298621e9629309f0e2c90c4d80d535c7d4e8ab07d29  c0_body.bin
~~~
{: .output}

#### Step 5: Verify the signature. 
Now we have all the information, including the CA’s public key, the CA’s signature, and the body of the server’s certificate. We can run our own program to verify whether the signature is valid or not. 
All of the necessary information have been given throughout the lab inorder for the user to successfully complete task 5.  
The following code is only an example.  
```c
/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
/*
Use BN_bn2hex(a) for hex string*
Use BN_bn2dec(a) for decimal string
*/
char *number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}



int main ()
{
//declaring the variables
BN_CTX *ctx = BN_CTX_new();
BIGNUM *m = BN_new();
BIGNUM *n = BN_new();
BIGNUM *e = BN_new();
BIGNUM *ver =BN_new();
BIGNUM *sig =BN_new();

//initializing the variables
BN_hex2bn(&n, "DCAE58904DC1C4301590355B6E3C8215F52C5CBDE3DBFF7143FA64258
0D4EE18A24DF066D00A736E1198361764AF379DFDFA4184AFC7AF8CFE1A734DCF33979
0A2968753832BB9A675482D1D56377BDA31321AD7ACAB06F4AA5D4BB74746DD2A93C3
902E798080EF13046A143BB59B92BEC207654EFCDAFCFF7AAEDC5C7E55310CE83907A4
D7BE2FD30B6AD2B1DF5FFE5774533B3580DDAE8E4498B39F0ED3DAE0D7F46B29AB44A
74B58846D924B81C3DA738B129748900445751ADD37319792E8CD540D3BE4C13F395E2E
B8F35C7E108E8641008D456647B0A165CEA0AA29094EF397EBE82EAB0F72A7300EFAC7
F4FD1477C3A45B2857C2B3F982FDB745589B");

BN_hex2bn(&e, "10001");

BN_hex2bn(&sig, "737085ef4041a76a43d5789c7b5548e6bc6b9986bafb0d038b78fe11f029a00ccd69140bc60
478b2cef087d5019dc4597a71fef06e9ec1a0b0912d1fea3d55c533050ccdc13518b06a68664cbf5621da5bd948b9
8c3521915ddc75d77a462c2227a66fd33a17ebbebd13c5122673c05da335896afb27d4ddaa74742e37e5013ba6d03
0b083d0a1c4752185b2e5fa670030a2bc53834dbfd6a883bbbcd6ed1cb31ef1580382008e9cef90f21a5fa2a306d
a5dbe9fda5da6e62fde588018d3f1627ba6a39faea86972638165ae8283a3b5978a9b2051ff1a3f61401e48d06b38f
9e1fa17d8774a88e63d36244fef0ab99f70f38327f8cf2a057510a18a0a8088cd");

//calculating ver=sig^e mod n to verify the certificate
BN_mod_exp(ver,sig,e,n,ctx);

//printing out the verified certificate
printBN("The verified certificate is ", ver);
return 0;
} 
```  
You will get the following output.  
~~~
The verified certificate is  01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D0609608648016503040201050004202C2A46BF245DAB54DDB47298621E9629309F0E2C90C4D80D535C7D4E8AB07D29 
~~~
{: .output}

> ## Callout
> The hashed certificate ' 2c2a46bf245dab54ddb47298621e9629309f0e2c90c4d80d535c7d4e8ab07d29' can be found in the verified certificate.
> Which means that the certificate is valid. 
{: .callout}




























