#include "commitment.h"

struct pairing_s myP;
struct BilinearMap myBL;

struct BilinearMap *pmyBL;

struct LinearFunction myLF;

struct KeyPair myKP;
struct KeyTriple myKT;

struct SecretKey sk;
struct EvaluationKey ek;
struct VerificationKey vk;

struct PublicKey pk;

element_t randomElements[n];
element_t messages[n][T];

struct AuthAndShare myAS[n];
struct AuthAndShare finalAS;

struct Authenticator myAuths[n];
struct Authenticator finalAuth;

int main()
{
	// Initializing libsodium
	if (sodium_init() < 0) 
	{
		puts("Error initializing sodium library!");
		return -1;
	}

	myBL.pairing = &myP;
	pmyBL = &myBL;

	struct CommitmentKey myCK;
	myCK.bm = &myBL;

	// Generating a LinearFunction
	for (int i = 0; i < n; i++)
	{
		myLF.f[i] = i;
	}

	ek.lf = myLF;

	myKP.pk = &pk;
	myKP.sk = &sk;

	myKT.sk = &sk;
	myKT.ek = &ek;
	myKT.vk = &vk;

	puts("1");

	// Calling VKeyGen to generate a KeyTriple
	VKeyGen(myLF, &myCK, &myKP, &myKT);

	// Generating m and r
	for (int i = 0; i < n; i++)
	{
		element_init_Zr(randomElements[i], myCK.bm->pairing);
	}
	
	for (int i = 0; i < n; i++)
	{
		for (int j = 0; j < T; j++)
		{
			element_init_Zr(messages[i][j], myCK.bm->pairing);
		}
	}

	// Generating.a dataset
	puts("2");
	int myDatasetBytes = sizeof(unsigned char)*3;
	unsigned char *myDataset = malloc(myDatasetBytes);
	*myDataset = 40;
	*(myDataset+1) = 41;
	*(myDataset+2) = 42;

	// Calling ProbGen n times
	for (int i = 0; i < n; i++)
	{
		myAS[i].auth = &myAuths[i];
		int ident = i;
		printf("i: %d\n",i);
		puts("2.01");
		element_init_G2(myAS[i].auth->Z, myCK.bm->pairing);
		puts("2.02");
		element_init_G1(myAS[i].auth->U, myCK.bm->pairing);
		element_init_G1(myAS[i].auth->V, myCK.bm->pairing);
		puts("2.03");
		for (int j = 0; j <= T; j++)
		{
			for (int k = 0; k < N; k++)
			{
				element_init_Zr(myAS[i].sshares[j][k], myCK.bm->pairing);
			}
		}
	
		ProbGen(sk, messages[i], &randomElements[i], myDataset, myDatasetBytes, &ident, &myCK, &myAS[i]);
	}

	puts("4");
	finalAS.auth = &finalAuth;
	puts("4.1");
	element_init_G2(finalAS.auth->Z, myCK.bm->pairing);
	puts("4.2");
	element_init_G1(finalAS.auth->U, myCK.bm->pairing);
	puts("4.3");
	element_init_G1(finalAS.auth->V, myCK.bm->pairing);
	puts("4.4");

	for (int j = 0; j <= T; j++)
	{
		for (int k = 0; k < N; k++)
		{
			element_init_Zr(finalAS.sshares[j][k], myCK.bm->pairing);
		}
	}

	// Calling compute to generate a final AuthAndShare object
	Compute(&ek, myAS, &myCK, &finalAS);
	puts("5");

	// If everything worked, Verify should return 1
	int a = Verify(&vk, &finalAS, &myCK, myDataset, myDatasetBytes);
	printf("Verify: %d\n",a);

}