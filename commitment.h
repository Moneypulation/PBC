#ifndef __COMMITMENT_H__
#define __COMMITMENT_H__
#include <stdio.h>
#include <stdlib.h>
#include <pbc.h>
#include <sodium.h>
#include <string.h>

// Global variables n, T and the security parameter lambda

#define lambda 256
#define n 256
#define T 2
#define N 8
#define t 4


/**
 *  A BilinearMap contains
 * 
 *  pairing     : A pairing object
 *  g_1			: An element of group G_1
 *  g_2 		: An element of group G_2
 *  g_t 		: An element of group G_T
 * 
 *  with e(g_1,g_2) = g_t
 */
struct BilinearMap
{
	struct pairing_s *pairing;
	element_t g1;
	element_t g2;
	element_t gt;
};


/**
 *  A CommitmentKey contains
 * 
 *  bm 		: A BilinearMap
 *  H 		: T+1 elements of group G_1
 * 
 *  with H_i = g_1^(a_i)
 *  with a_i being a random Z_r ring element
 */
struct CommitmentKey
{
	struct BilinearMap *bm;
	element_t H[T+1];
};


/**
 *  A PublicKey contains
 * 
 *  pkSig	: The public key of the signature scheme (in our case HMAC-SHA-512)
 *  Y 		: An element of group G_2
 *  h2 		: n elements of group G_T
 *
 *  with h2_i = g_t^(b_i) 
 *  with b_i being random Z_r ring elements
 */
struct PublicKey
{
	unsigned char pkSig[crypto_sign_PUBLICKEYBYTES];
	element_t Y;
	element_t h2[n];
};


/**
 *  A SecretKey contains
 * 
 *  skSig	: The secret key of the signature scheme (in our case HMAC-SHA-512)
 *  y 		: A randomly selected Z_r ring element
 *  H2 		: n elements of group G_1
 *  seedK 	: A key for the signature scheme
 *  seedK2	: A key for the signature scheme
 *
 *  with PublicKey.Y = g_2^y
 *  and H_i = g_1^(b_i)
 *  with b_i being the same randomly selected Z_r ring elements from PublicKey
 */
struct SecretKey
{
	unsigned char skSig[crypto_sign_SECRETKEYBYTES];
	element_t y;
	element_t H2[n];
	unsigned char seedK[crypto_auth_hmacsha512_KEYBYTES];
	unsigned char seedK2[crypto_auth_hmacsha512_KEYBYTES];
};

/**
 *  A KeyPair contains
 * 
 *  pk	: A PublicKey
 *  sk 	: A SecretKey
 */
struct KeyPair
{
	struct PublicKey *pk;
	struct SecretKey *sk;
};


/**
 *  An Authenticator contains
 * 
 *  oDelta		: The product of signing the concatenation of a randomly selected dataset delta with Z,
 *  oDeltaBytes : The amount of bytes oDelta holds
 *  Z 			: An element of group G_2
 *  U 			: An element of group G_1
 *  V 			: An element of group G_1
 *  
 *  with Z = g_2^z
 *  with z being the product of signing delta with the key seedK
 *  and U = g_1^u
 *  with u being the product of signing the concatenation of delta with an identifier tau with the key seedK2
 *  and V = (U * SecretKey.H2_tau * CommitmentKey.H_0^(y*r) * CommitmentKeyH_1^(y * m[1]) * ... * CommitmentKey.H_T^(y * m[T]))^(1/z)
 */
struct Authenticator
{
	unsigned char *oDelta;
	int oDeltaBytes;
	element_t Z;
	element_t U;
	element_t V;
};


/**
 *  A LinearFunction contains
 * 
 *  f	: n signed long ints
 */
struct LinearFunction
{
	signed long int f[n];
};

/**
 *  An EvaluationKey contains
 * 
 *  lf	: A linearFunction
 */
struct EvaluationKey
{
	struct LinearFunction lf;
};


/**
 *  A VerificationKey contains
 * 
 *  *pk	: A PublicKey
 *  *fc : A FunctionCommit
 */
struct VerificationKey
{
	struct PublicKey *pk;
	element_t fc;
};


/**
 *  A KeyTriple contains
 * 
 *  *sk	: A SecretKey
 *  *ek : An EvaluationKey
 *  *vk : A VerificationKey
 */
struct KeyTriple
{
	struct SecretKey *sk;
	struct EvaluationKey *ek;
	struct VerificationKey *vk;
};


/**
 *  An AuthAndShare contains
 * 
 *  *auth			: An Authenticator
 *  sshares[T+1][N] : T+1 secret shares being a list of N Z_r ring elements
 */
struct AuthAndShare
{
	struct Authenticator *auth;
	element_t sshares[T+1][N];
};


// Function declarations
void Setup(struct CommitmentKey *CK);
void KeyGen(struct CommitmentKey *CK, struct KeyPair *KP);
void PublicCommit(struct CommitmentKey *CK, element_t m[T], element_t r, element_t *ret);
void PrivateCommit(struct SecretKey sk, element_t m[T], element_t r, const unsigned char* dataset, int datasetBytes, int *identifier, struct CommitmentKey *CK, struct Authenticator *auth);
void FunctionCommit(struct PublicKey pk, struct LinearFunction lf, struct CommitmentKey *CK, element_t *ret);
void Eval(struct LinearFunction lf, struct Authenticator myAuthenticators[n], struct CommitmentKey *CK, struct Authenticator *auth);
int PublicDecommit(struct CommitmentKey *CK, element_t m[T], element_t r, element_t c);
int FunctionVerify(struct PublicKey pk, struct Authenticator auth, element_t c, element_t f, const unsigned char* dataset, int datasetBytes, struct CommitmentKey *CK);

void Share(element_t *m, element_t sshares[N], struct CommitmentKey *CK);
void Reshare(element_t sshares[N], element_t sshares2[N], struct CommitmentKey *CK);
void Reconstruct(signed long int subset[t], element_t sshares[N], element_t *ret, struct CommitmentKey *CK);
void VKeyGen(struct LinearFunction lf, struct CommitmentKey *CK, struct KeyPair *kp, struct KeyTriple *kt);
void ProbGen(struct SecretKey sk, element_t m[T], element_t *r, const unsigned char *dataset, int datasetBytes, int *identifier, struct CommitmentKey *CK, struct AuthAndShare *as);
void Compute(struct EvaluationKey *ek, struct AuthAndShare as[N], struct CommitmentKey *CK, struct AuthAndShare *asReturn);
int Verify(struct VerificationKey *vk, struct AuthAndShare *as, struct CommitmentKey *CK, const unsigned char *dataset, int datasetBytes);
#endif // __COMMITMENT_H__
