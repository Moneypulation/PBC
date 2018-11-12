#include "commitment.h"
#include <sys/time.h>


uint64_t getTimeDifference(struct timespec *t1, struct timespec *t2);

struct pairing_s myP;
struct BilinearMap myBL;

struct BilinearMap *pmyBL;

struct PublicKey myPK;
struct SecretKey mySK;

struct KeyPair myKP;

element_t randomElements[n];
element_t messages[n][T];

struct Authenticator myAuths[n];

struct LinearFunction myLF;	

struct Authenticator finalAuth;

element_t finalMessage[T];
element_t finalRandom;

element_t myPublicCommit;

int main(int argc, char* argv[])
{
	// Initializing libsodium
	if (sodium_init() < 0) 
	{
		puts("Error initializing sodium library!");
		return -1;
	}

	/**
	*  The functions are going to be called in this scheme:
	*
	*	1. Call Setup() to generate the CommitmentKey
	*	2. Call KeyGen() to generate a KeyPair
	*	3. Generate n random Z_r ring elements r
	*	4. Generate n random messages, whereas a message is a vector of size T 
	*	   containing Z_r ring elements
	*	5. Generate an arbitrary long dataset delta
	*	6. Call PrivateCommit() n times with identifier = 1...n to generate
	*	   n Authenticators
	*	7. Generate a LinearFunction with random values in it
	*	8. Call FunctionCommit() to generate a FunctionCommitment
	*	9. Call Eval() to generate a final Authenticator
	*  10. Generate a final message: 	sum f[i]*m_i, i=0 to n
	*  11. Generate a final element r: 	sum f[i]*r_i, i=0 to n
	*  12. Call PublicCommit() to generate a Commitment
	*  13. Call FunctionVerify(). It should output 1
	*
	*/

	struct timespec tSetupBegin, tSetupEnd, tKeygenBegin, tKeygenEnd, tPrivatecommitBegin, tPrivatecommitEnd,
	tPubliccommitBegin, tPubliccommitEnd, tFunctioncommitBegin, tFunctioncommitEnd, tEvalBegin, tEvalEnd,
	tFunctionverifyBegin, tFunctionverifyEnd;


	// ------ 1 ------ //
	
	
	myBL.pairing = &myP;
	pmyBL = &myBL;

	struct CommitmentKey myCK;
	myCK.bm = &myBL;

	clock_gettime(CLOCK_MONOTONIC_RAW, &tSetupBegin);
	printf("%s","Calling Setup...");
	Setup(&myCK);
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tSetupEnd);

	// ------ 2 ------ //
	myKP.pk = &myPK;
	myKP.sk = &mySK;
	clock_gettime(CLOCK_MONOTONIC_RAW, &tKeygenBegin);
	printf("%s","Calling KeyGen...");
	KeyGen(&myCK, &myKP);
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tKeygenEnd);
	// ------ 3 ------ //
	

	for (int i = 0; i < n; i++)
	{
		element_init_Zr(randomElements[i], myCK.bm->pairing);
	}
	// ------ 4 ------ //
	// old: element_t messages[n][T];
	
	for (int i = 0; i < n; i++)
	{
		for (int j = 0; j < T; j++)
		{
			element_init_Zr(messages[i][j], myCK.bm->pairing);
		}
	}
	// ------ 5 ------ //
	int myDatasetBytes = sizeof(unsigned char)*3;
	unsigned char *myDataset = malloc(myDatasetBytes);
	*myDataset = 40;
	*(myDataset+1) = 41;
	*(myDataset+2) = 42;

	// ------ 6 ------ //
	clock_gettime(CLOCK_MONOTONIC_RAW, &tPrivatecommitBegin);
	printf("%s %d %s", "Calling PrivateCommit", n, "times...");
	for (int i = 0; i < n; i++)
	{
		int ident = i;
		element_init_G2(myAuths[i].Z, myCK.bm->pairing);
		element_init_G1(myAuths[i].U, myCK.bm->pairing);
		element_init_G1(myAuths[i].V, myCK.bm->pairing);
		PrivateCommit(*(myKP.sk), messages[i], randomElements[i], myDataset, myDatasetBytes, &ident, &myCK, &myAuths[i]);
	}
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tPrivatecommitEnd);

	// ------ 7 ------ //

	for (int i = 0; i < n; i++)
	{
		myLF.f[i] = i;
	}

	// ------ 8 ------ //
	element_t functionCommit;
	element_init_GT(functionCommit, myCK.bm->pairing);

	clock_gettime(CLOCK_MONOTONIC_RAW, &tFunctioncommitBegin);
	printf("%s","Calling FunctionCommit...");
	FunctionCommit(*(myKP.pk), myLF, &myCK, &functionCommit);
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tFunctioncommitEnd);

	// ------ 9 ------ //
	
	element_init_G2(finalAuth.Z, myCK.bm->pairing);
	element_init_G1(finalAuth.U, myCK.bm->pairing);
	element_init_G1(finalAuth.V, myCK.bm->pairing);

	clock_gettime(CLOCK_MONOTONIC_RAW, &tEvalBegin);
	printf("%s","Calling Eval...");
	Eval(myLF, myAuths, &myCK, &finalAuth);
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tEvalEnd);


	// ------ 10 + 11 ------ //

	for (int j = 0; j < T; j++)
	{
		element_init_Zr(finalMessage[j], myCK.bm->pairing);
	}

	element_init_Zr(finalRandom, myCK.bm->pairing);

	for (int i = 0; i < n; i++)
	{
		element_mul_si(randomElements[i], randomElements[i], myLF.f[i]);
		element_add(finalRandom, finalRandom, randomElements[i]);
		for (int j = 0; j < T; j++)
		{
			element_mul_si(messages[i][j], messages[i][j], myLF.f[i]);
			element_add(finalMessage[j], finalMessage[j], messages[i][j]);
		}
	}


	// ------ 12 ------ //
	element_init_G1(myPublicCommit, myCK.bm->pairing);

	clock_gettime(CLOCK_MONOTONIC_RAW, &tPubliccommitBegin);
	printf("%s","Calling PublicCommit...");
	PublicCommit(&myCK, finalMessage, finalRandom, &myPublicCommit);
	printf("%s\n","Done");
	clock_gettime(CLOCK_MONOTONIC_RAW, &tPubliccommitEnd);

	// ------ 13 ------ //
	clock_gettime(CLOCK_MONOTONIC_RAW, &tFunctionverifyBegin);
	printf("%s\n","Calling FunctionVerify...");
	int result = FunctionVerify(*(myKP.pk), finalAuth, myPublicCommit, functionCommit, myDataset, myDatasetBytes, &myCK);
	printf("%s %d\n", "FunctionVerify:", result);
	clock_gettime(CLOCK_MONOTONIC_RAW, &tFunctionverifyEnd);

	uint64_t d1 = getTimeDifference(&tSetupBegin, &tSetupEnd);
	uint64_t d2 = getTimeDifference(&tKeygenBegin, &tKeygenEnd);
	uint64_t d3 = getTimeDifference(&tPrivatecommitBegin, &tPrivatecommitEnd);
	uint64_t d4 = getTimeDifference(&tFunctioncommitBegin, &tFunctioncommitEnd);
	uint64_t d5 = getTimeDifference(&tEvalBegin, &tEvalEnd);
	uint64_t d6 = getTimeDifference(&tPubliccommitBegin, &tPubliccommitEnd);
	uint64_t d7 = getTimeDifference(&tFunctionverifyBegin, &tFunctionverifyEnd);
	uint64_t d8 = getTimeDifference(&tSetupBegin, &tFunctionverifyEnd);

	printf("%d;%d;%d;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%llu\n", lambda,n,T,d1,d2,d3,d4,d5,d6,d7,d8);

	
}

uint64_t getTimeDifference(struct timespec *t1, struct timespec *t2)
{
	uint64_t delta_us = (t2->tv_sec - t1->tv_sec) * 1000000 + (t2->tv_nsec - t1->tv_nsec) / 1000;
	return delta_us/1000;
}