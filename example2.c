#include "commitment.h"

struct pairing_s myP;
struct BilinearMap myBL;

struct BilinearMap *pmyBL;

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

	// Setting the pairing parameters
	pbc_param_t typeFParam;
	pbc_param_init_f_gen(typeFParam, lambda);
	pairing_init_pbc_param(myCK.bm->pairing, typeFParam);

	// Generating a random message m
	element_t m;
	element_init_Zr(m, myCK.bm->pairing);
	element_random(m);

	element_t sshares[N];

	for (int i = 0; i < N; i++)
	{
		element_init_Zr(sshares[i], myCK.bm->pairing);
	}

	// Calling Share to generate secret shares
	Share(&m, sshares, &myCK);

	element_t sshares_new[N];

	for (int i = 0; i < N; i++)
	{
		element_init_Zr(sshares_new[i], myCK.bm->pairing);
	}

	// Calling Reshare to generate new secret messages
	Reshare(sshares, sshares_new, &myCK);

	signed long int subset[t];

	// Choosing a subset
	for (int i = 0; i < t; i++)
	{
		subset[i] = i;
	}

	element_t ret;
	element_init_Zr(ret, myCK.bm->pairing);

	// Calling reconstruct to generate a message m'
	Reconstruct(subset, sshares_new, &ret, &myCK);

	// If everything worked, m = m' should hold now
	if (element_cmp(ret, m) == 0)
	{
		puts("m = m'");
	}
	else
	{
		puts("m != m'\nSomething went wrong\n");
	}




}