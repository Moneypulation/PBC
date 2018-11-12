#include "commitment.h"


/**
*  Generates a CommitmenKey
*
*  @return *CK - A CommitmentKey
*/
void Setup(struct CommitmentKey *CK)
{
	// We are using Type F params only
	pbc_param_t typeFParam;
	pbc_param_init_f_gen(typeFParam, lambda);
	pairing_init_pbc_param(CK->bm->pairing, typeFParam);
	
	// Initialize g_1, g_2 and g_t with random elements of their group
	element_init_G1(CK->bm->g1, CK->bm->pairing);
	element_random(CK->bm->g1);

	element_init_G2(CK->bm->g2, CK->bm->pairing);
	element_random(CK->bm->g2);

	element_init_GT(CK->bm->gt, CK->bm->pairing);
	pairing_apply(CK->bm->gt, CK->bm->g1, CK->bm->g2, CK->bm->pairing);

	element_t a[T+1];
	element_t current;
	int doubleFound = 0;
	do
	{
		for (int i = 0; i < T+1; i++)
		{
			// Initialize a's
			element_init_Zr(a[i], CK->bm->pairing);
			element_random(a[i]);
		}
		// Check if two a's have the same value. If so, give them new random values
		for(int i = 0; i < T+1; i++)
		{
			for (int j = i+1; j < T+1; j++)
			{
				if (element_cmp(a[i], a[j]) == 0)
				{
					doubleFound = 1;
					break;
				}
			}
			if (doubleFound)
				break;
		}
	} while (doubleFound);

	// Generate the H's of the CommitmentKey
	for (int i = 0; i < T+1; i++)
	{
		element_init_G1(CK->H[i], CK->bm->pairing);
		element_pow_zn(CK->H[i], CK->bm->g1 ,a[i]);
	}
}


/**
*  Generates a KeyPair (PublicKey, SecretKey) out of the CommitmentKey
*
*  @param 	*CK - A CommitmentKey
*
*  @return 	*KP - A KeyPair
*/
void KeyGen(struct CommitmentKey *CK, struct KeyPair *KP)
{
	// Generate a random Z_r ring element y
	element_t y;
	element_init_Zr(y, CK->bm->pairing);
	element_random(y);

	// Calcute Y = g_2^y
	element_t Y;
	element_init_G2(Y, CK->bm->pairing);
	element_pow_zn(Y, CK->bm->g2 ,y);

	int doubleFound = 0;
	element_t b[n];
	element_t current;

	// Same as in Setup()
	// Generate n random Z_r ring elements b and check if they are distinct
	do
	{
		doubleFound = 0;
		for (int i = 0; i < n; i++)
		{
			element_init_Zr(b[i], CK->bm->pairing);
			element_random(b[i]);
		}

		for(int i = 0; i < n; i++)
		{
			for (int j = i+1; j < n; j++)
			{
				if (element_cmp(b[i], b[j]) == 0)
				{
					doubleFound = 1;
					break;
				}
			}
			if (doubleFound)
				break;
		}
	} while (doubleFound);

	
	// Generate the H2's of the SecretKey
	for (int i = 0; i < n; i++)
	{
		element_init_G1(KP->sk->H2[i], CK->bm->pairing);
		element_pow_zn(KP->sk->H2[i], CK->bm->g1 ,b[i]);
	}

	// Generate the h2's of the PublicKey
	for (int i = 0; i < n; i++)
	{
		element_init_GT(KP->pk->h2[i], CK->bm->pairing);
		element_pow_zn(KP->pk->h2[i], CK->bm->gt ,b[i]);
	}

	// Generate public and secret key for the signature scheme
	crypto_sign_keypair(KP->pk->pkSig, KP->sk->skSig);

	element_init_G2(KP->pk->Y, CK->bm->pairing);
	element_set(KP->pk->Y, Y);

	element_init_Zr(KP->sk->y, CK->bm->pairing);
	element_set(KP->sk->y, y);

	// Generate the two keys seedK and seedK2 for the signature scheme
	crypto_auth_hmacsha512_keygen(KP->sk->seedK);
	crypto_auth_hmacsha512_keygen(KP->sk->seedK2);
}


/**
*  Generates a Commitment
*
*  @param 	*CK  - A CommitmentKey
*  @param 	m[T] - A message m being a vector of size T of Z_r ring elements
*  @param 	r 	 - A randomly generated Z_r ring element
*
*  @return 	*ret - A Commitment
*/
void PublicCommit(struct CommitmentKey *CK, element_t m[T], element_t r, element_t *ret)
{
	element_t powHelper, powHelper2;
	element_t firstH;

	// Initialize temp elements
	element_init_G1(powHelper, CK->bm->pairing);
	element_init_G1(powHelper2, CK->bm->pairing);
	element_init_G1(firstH, CK->bm->pairing);

	element_pow_zn(powHelper, CK->H[1], m[0]);
	element_set(*ret, powHelper);

	for (int j = 2; j <= T; j++)
	{
		element_pow_zn(powHelper2, CK->H[j], m[j-1]);
		element_mul(*ret, *ret, powHelper2);
	}

	// Equals H_0^r
	element_pow_zn(firstH, CK->H[0], r);
	element_mul(*ret, *ret, firstH);
}


/**
*  Generates an Authenticator
*
*  @param 	sk 	 		 - A SecretKey
*  @param 	m[T] 		 - A message
*  @param 	r 	 		 - A randomly selected Z_r ring element
*  @param 	*dataset 	 - An arbirary long dataset
*  @param 	datasetBytes - The amount of bytes dataset holds
*  @param 	*identifier  - An identifier with 0 <= identifier <= n
*  @param 	*CK 		 - A CommitmentKey
*
*  @return *auth 		 - An Authenticator
*/
void PrivateCommit(struct SecretKey sk, element_t m[T], element_t r, const unsigned char* dataset, int datasetBytes, int *identifier, struct CommitmentKey *CK, struct Authenticator *auth)
{
	element_t Z, z;
	unsigned char* Z_converted;
	unsigned char hash_z[crypto_auth_hmacsha512_BYTES];

	// Hashing the dataset with seedK and saving it in hash_z
	crypto_auth_hmacsha512(hash_z, dataset, datasetBytes, sk.seedK);
	element_init_Zr(z, CK->bm->pairing);
	element_init_G2(Z, CK->bm->pairing);

	// Export hash_z into a Z_r ring element
	element_from_bytes(z, hash_z);
	// Z = g_2^z
	element_pow_zn(Z, CK->bm->g2, z);
	// Export Z into an unsigned char pointer to be able to sign it later
	int bytesOfZ = element_length_in_bytes(Z);
	Z_converted = malloc(bytesOfZ);
	element_to_bytes(Z_converted, Z);

	// Amount of bytes the concatenation of Z and dataset is going to require
	int bytesTotal = datasetBytes + bytesOfZ;

	// Concatenating Z with dataset
	unsigned char* concatenated = malloc(bytesTotal);
	memcpy((void*)concatenated, (const void*) dataset, datasetBytes);
	memcpy((void*)(concatenated + datasetBytes), (const void*) Z_converted, bytesOfZ);
	// Signing the concatenation
	unsigned char *signed_message = malloc(crypto_sign_BYTES + bytesTotal);
	unsigned long long smlen;
	crypto_sign(signed_message, &smlen, concatenated, (unsigned long long) bytesTotal, sk.skSig);

	// Calculating u = Concatenation of dataset with identifier
	unsigned char hash_u[crypto_auth_hmacsha512_BYTES];
	unsigned char* datasetAndIdentifier = malloc(datasetBytes + sizeof(int));
	memcpy((void*)datasetAndIdentifier, (const void*) dataset, datasetBytes);
	memcpy((void*)(datasetAndIdentifier + datasetBytes), (void*) identifier, sizeof(int));

	// Hashing u with seedK2 and saving it in hash_u
	crypto_auth_hmacsha512(hash_u, datasetAndIdentifier, sizeof(datasetAndIdentifier), sk.seedK2);

	element_t u, U;
	element_init_G1(U, CK->bm->pairing);
	element_init_Zr(u, CK->bm->pairing);
	element_from_bytes(u, hash_u);

	// U = g_1^u
	element_pow_zn(U, CK->bm->g1, u);

	element_t V;
	element_init_G1(V, CK->bm->pairing);

	element_mul(V, sk.H2[*identifier], U);
	// Initializing temp elements
	element_t yr, H0yr;
	element_init_Zr(yr, CK->bm->pairing);
	element_init_G1(H0yr, CK->bm->pairing);

	// Calculating V
	element_mul(yr, sk.y, r);
	element_pow_zn(H0yr, sk.H2[0], yr);

	element_mul(V, V, H0yr);
	for (int i = 1; i <= T; i++)
	{
		element_t tmp, tmpH;
		element_init_Zr(tmp, CK->bm->pairing);
		element_init_G1(tmpH, CK->bm->pairing);
		element_mul(tmp, sk.y, m[i-1]);
		element_pow_zn(tmpH, CK->H[i], tmp);
		element_mul(V, V, tmpH);
	}
	element_t plainOne, oneDivByZ;

	element_init_Zr(plainOne, CK->bm->pairing);
	element_init_Zr(oneDivByZ, CK->bm->pairing);
	element_set1(plainOne);
	element_div(oneDivByZ, plainOne, z);
	element_pow_zn(V, V, oneDivByZ);

	// Saving the results in the authenticator
	auth->oDelta = malloc(crypto_sign_BYTES + bytesTotal);
	memcpy(auth->oDelta, signed_message, crypto_sign_BYTES + bytesTotal);
	auth->oDeltaBytes = crypto_sign_BYTES + bytesTotal;
	element_set(auth->Z, Z);
	element_set(auth->U, U);
	element_set(auth->V, V);
}


/**
*  Generates a FunctionCommitment
*
*  @param  pk - A PublicKey
*  @param  lf - A LinearFunction
*  @param *CK - A CommitmentKey
*
*  @return *ret - A FunctionCommitment
*/
void FunctionCommit(struct PublicKey pk, struct LinearFunction lf, struct CommitmentKey *CK, element_t *ret)
{
	// Simply calculating: product h2_i^f_i, i=0 to n
	element_set(*ret, pk.h2[0]);

	element_t convertedFirst;
	element_init_Zr(convertedFirst, CK->bm->pairing);

	element_set_si(convertedFirst, lf.f[0]);
	element_pow_zn(*ret, *ret, convertedFirst);

	for (int i = 1; i < n; i++)
	{
		element_t converted, hifi;
		element_init_Zr(converted, CK->bm->pairing);
		element_init_GT(hifi, CK->bm->pairing);
		element_set_si(converted, lf.f[i]);
		element_pow_zn(hifi, pk.h2[i], converted);
		element_mul(*ret, *ret, hifi);
	}
}


/**
*  Generates a final Authenticator
*
*  @param lf 				  - A LinearFunction
*  @param myAuthenticators[n] - n Authenticators
*  @param *CK 				  - A CommitmentKey
*
*  @return *auth 			  - A final Authenticator
*/
void Eval(struct LinearFunction lf, struct Authenticator myAuthenticators[n], struct CommitmentKey *CK, struct Authenticator *auth)
{
	// Set auth->oDelta = myAuthenticators[0].oDelta
	auth->oDelta = malloc(myAuthenticators[0].oDeltaBytes);
	memcpy(auth->oDelta, myAuthenticators[0].oDelta, myAuthenticators[0].oDeltaBytes);
	auth->oDeltaBytes = myAuthenticators[0].oDeltaBytes;

	// Set auth->Z = myAuthenticators[0].Z
	element_set(auth->Z, myAuthenticators[0].Z);

	// Calculate final U
	element_t finalU;
	element_init_G1(finalU, CK->bm->pairing);
	element_set(finalU, myAuthenticators[0].U);

	element_t convertedFirstU;
	element_init_Zr(convertedFirstU, CK->bm->pairing);
	element_set_si(convertedFirstU, lf.f[0]);
	element_pow_zn(finalU, finalU, convertedFirstU);

	// Calculate final V
	element_t finalV;
	element_init_G1(finalV, CK->bm->pairing);
	element_set(finalV, myAuthenticators[0].V);

	element_t convertedFirstV;
	element_init_Zr(convertedFirstV, CK->bm->pairing);
	element_set_si(convertedFirstV, lf.f[0]);
	element_pow_zn(finalV, finalV, convertedFirstV);

	for (int i = 1; i < n; i++)
	{
		// U
		element_t converted, uifi;
		element_init_Zr(converted, CK->bm->pairing);
		element_init_G1(uifi, CK->bm->pairing);
		element_set_si(converted, lf.f[i]);
		element_pow_zn(uifi, myAuthenticators[i].U, converted);
		element_mul(finalU, finalU, uifi);

		// V
		element_t convertedV, vifi;
		element_init_Zr(convertedV, CK->bm->pairing);
		element_init_G1(vifi, CK->bm->pairing);
		element_set_si(convertedV, lf.f[i]);
		element_pow_zn(vifi, myAuthenticators[i].V, convertedV);
		element_mul(finalV, finalV, vifi);
	}

	// Set U and V
	element_set(auth->U, finalU);
	element_set(auth->V, finalV);
}


/**
*  Returns 1 or 0 depending on whether the conditions hold
*
*  @param pk 			- A PublicKey
*  @param auth 			- An Authenticator
*  @param c 			- A Commitment
*  @param f 			- A FunctionCommitment
*  @param *dataset 		- An arbitrary long dataset
*  @param datasetBytes  - The amount of bytes dataset holds
*  @param *CK 			- A CommitmentKey
*
*  @return 1 if signature check returns true and e(V,Z) = e(U,g_2) * F * e(C,Y) holds, otherwise 0
*/
int FunctionVerify(struct PublicKey pk, struct Authenticator auth, element_t c, element_t f, const unsigned char *dataset, int datasetBytes, struct CommitmentKey *CK)
{
	// Export auth.Z into an unsigned char pointer to be able to sign it later
	// (Same Procedure as in PrivateCommit())
	unsigned char* Z_converted;
	int bytesOfZ = element_length_in_bytes(auth.Z);
	Z_converted = malloc(bytesOfZ);
	element_to_bytes(Z_converted, auth.Z);

	// The amount of bytes the concatenation of dataset and Z is going to require
	unsigned long long bytesTotal = datasetBytes + bytesOfZ;
	unsigned long long *pbytesTotal = malloc(sizeof(unsigned long long));
	*pbytesTotal = bytesTotal;

	// Concatenating dataset with Z
	unsigned char* concatenated = malloc(bytesTotal);
	memcpy((void*)concatenated, (void*) dataset, datasetBytes);
	memcpy((void*)(concatenated + datasetBytes), (void*) Z_converted, bytesOfZ);

	// Signature check
	if (crypto_sign_open(concatenated, pbytesTotal,
	 (unsigned const char*) auth.oDelta, auth.oDeltaBytes,
	  pk.pkSig) == -1)
	{
		printf("FunctionVerify: Signature invalid\n");
		return 0;
	}
	else
	{
		// Applying pairings
		element_t eVZ, eUg2, eCY;
		element_t multResult;
		element_init_GT(multResult, CK->bm->pairing);

		element_init_GT(eVZ, CK->bm->pairing);
		element_init_GT(eUg2, CK->bm->pairing);
		element_init_GT(eCY, CK->bm->pairing);

		pairing_apply(eVZ, auth.V, auth.Z, CK->bm->pairing);
		pairing_apply(eUg2, auth.U, CK->bm->g2, CK->bm->pairing);
		pairing_apply(eCY, c, pk.Y, CK->bm->pairing);

		element_mul(multResult, eUg2, eCY);
		element_mul(multResult, multResult, f);
		if (element_cmp(multResult, eVZ) == 0)
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
}

int PublicDecommit(struct CommitmentKey *CK, element_t m[T], element_t r, element_t c)
{
	element_t pubCommit;
	element_t *pElement = &pubCommit;
	PublicCommit(CK, m, r, pElement);
	if (element_cmp(*pElement, c))
	{
		return 0;
	}
	else
	{
		return 1;
	}
}


/**
*  Generates secret shares from a message
*
*  @param 	*m  - A message (in this case only a single element, no vector)
*  @param 	*CK - A CommitmentKey
*
*  @return 	sshares[N] - The secret shares as an array of N Z_r ring elements
*/
void Share(element_t *m, element_t sshares[N], struct CommitmentKey *CK)
{
	// Choose t-1 a's uniformly at random
	element_t a[t-1];

	for (int i = 0; i < (t-1); i++)
	{
		element_init_Zr(a[i], CK->bm->pairing);
		element_random(a[i]);
	}

	// Compute s_j = m + sum(a_j * j^i) j=1,..,N
	for (signed long int j = 0; j < N; j++)
	{
		element_t aiji;
		element_init_Zr(aiji, CK->bm->pairing);

		for (signed long int k = 1; k < t; k++)
		{
			element_t jAsElement;
			element_init_Zr(jAsElement, CK->bm->pairing);
			element_set_si(jAsElement, j);

			element_t kAsElement;
			element_init_Zr(kAsElement, CK->bm->pairing);
			element_set_si(kAsElement, k);

			element_pow_zn(jAsElement, jAsElement, kAsElement);

			element_mul(aiji, a[k-1], jAsElement);
		}
		element_add(sshares[j], aiji, *m);
	}
}


/**
*  Generates new secret shares out of existing ones
*
*  @param 	ssahres[N]  - The secret shares
*  @param 	*CK 		- A CommitmentKey
*
*  @return 	sshares2[N] - The new secret shares
*/
void Reshare(element_t sshares[N], element_t sshares2[N], struct CommitmentKey *CK)
{
	element_t ssharesMulti[N][N];

	for (int i = 0; i < N; i++)
	{
		for (int j = 0; j < N; j++)
		{
			element_init_Zr(ssharesMulti[i][j], CK->bm->pairing);
		}
	}

	// Call Share(0) N times
	for (int i = 0; i < N; i++)
	{
		element_t nullElement;
		element_init_Zr(nullElement, CK->bm->pairing);
		element_set0(nullElement);

		Share(&nullElement, ssharesMulti[i], CK);
	}

	// Then compute the new secret shares
	for (int i = 0; i < N; i++)
	{
		element_t bigSum;
		element_init_Zr(bigSum, CK->bm->pairing);
		element_set0(bigSum);

		for (int j = 0; j < N; j++)
		{
			element_add(bigSum, bigSum, ssharesMulti[j][i]);
		}

		element_add(bigSum, bigSum, sshares[i]);

		element_set(sshares2[i], bigSum);
	}
}


/**
*  Generates a new message from secret shares and a subset
*
*  @param 	subset[t]   - A subset of {1,...,N} of size t
*  @param 	sshares[N] 	- The secret shares
*  @param 	*CK			- A CommitmentKey
*
*  @return 	*ret 		- m 
*/
void Reconstruct(signed long int subset[t], element_t sshares[N], element_t *ret, struct CommitmentKey *CK)
{
	// Initialize the l's
	element_t l[t];
	for (int i = 0; i < t; i++)
	{
		element_init_Zr(l[i], CK->bm->pairing);
		element_set1(l[i]);
	}
	
	// l_j = product( i / (i - j) ) ,i and j elements of subset with i =! j
	for (signed long int j = 0; j < t; j++)
	{
		element_t jAsElement;
		element_init_Zr(jAsElement, CK->bm->pairing);
		element_set_si(jAsElement, subset[j]);

		for (signed long int i = 0; i < t; i++)
		{
			if (i == j)
				continue;
			element_t iAsElement;
			element_init_Zr(iAsElement, CK->bm->pairing);
			element_set_si(iAsElement, subset[i]);

			element_t iMinusj;
			element_init_Zr(iMinusj, CK->bm->pairing);
			element_sub(iMinusj, iAsElement, jAsElement);

			element_t division;
			element_init_Zr(division, CK->bm->pairing);
			element_div(division, iAsElement, iMinusj);

			element_mul(l[j], l[j], division);
		}
	}

	// Compute m = sum(s_j * l_j) , j element of subset 
	element_set0(*ret);

	for (int j = 0; j < t; j++)
	{
		element_t sjlj;
		element_init_Zr(sjlj, CK->bm->pairing);
		element_mul(sjlj, sshares[subset[j]], l[j]);

		element_add(*ret, *ret, sjlj);
	}
}


/**
*  Generates SecretKey, VerificationKey and EvaluationKey
*
*  @param 	lf  	- A linear function
*  @param 	*CK 	- A CommitmentKey
*  @param 	*kp 	- A KeyPair
*
*  @return 	*kt 	- A KeyTriple
*/
void VKeyGen(struct LinearFunction lf, struct CommitmentKey *CK, struct KeyPair *kp, struct KeyTriple *kt)
{
	Setup(CK);
	KeyGen(CK, kp);

	element_init_GT(kt->vk->fc, CK->bm->pairing);

	FunctionCommit(*(kp->pk), lf, CK, &(kt->vk->fc));
	kt->vk->pk = kp->pk;
	kt->sk = kp->sk;
	kt->ek->lf = lf;
}


/**
*  Generates an AuthAndShare object
*
*  @param 	sk  		 - A SecretKey
*  @param 	m[T] 		 - A message being a vector of size t
*  @param 	*r 			 - A Z_r ring element
*  @param 	*dataset  	 - An arbitrary long dataset
*  @param 	datasetBytes - The amount of bytes dataset holds
*  @param 	*identifier  - An identifier
*  @param 	*CK 		 - A CommitmentKey
*
*  @return 	*as 		 - An AuthAndShare object
*/
void ProbGen(struct SecretKey sk, element_t m[T], element_t *r, const unsigned char *dataset, int datasetBytes, int *identifier, struct CommitmentKey *CK, struct AuthAndShare *as)
{
	PrivateCommit(sk, m, *r, dataset, datasetBytes, identifier, CK, as->auth);
	Share(r, as->sshares[0], CK);

	for (int j = 1; j <= T; j++)
	{
		Share(&m[j-1], as->sshares[j], CK);
	}
}


/**
*  Generates an AuthAndShare object out of n existing ones
*
*  @param 	*ek 		- An EvaluationKey
*  @param 	as[N] 		- n AuthAndShare objects
*  @param 	*CK 		- A CommitmentKey
*
*  @return 	*asReturn 	- An AuthAndShare object
*/
void Compute(struct EvaluationKey *ek, struct AuthAndShare as[n], struct CommitmentKey *CK, struct AuthAndShare *asReturn)
{
	// Copy only the authenticator objects from as to pass them as parameter in Eval
	struct Authenticator allAuths[n];
	for (int i = 0; i < n; i++)
	{
		allAuths[i] = *(as[i].auth);
	}

	Eval(ek->lf, allAuths, CK, asReturn->auth);

	for (int k = 0; k < N; k++)
	{
		for (int j = 0; j <= T; j++)
		{
			element_t fs;
			element_t bigSum;
			element_init_Zr(fs, CK->bm->pairing);
			element_init_Zr(bigSum, CK->bm->pairing);
			element_set0(bigSum);

			for (int i = 0; i < n; i++)
			{
				element_t temp;
				element_init_Zr(temp, CK->bm->pairing);
				element_set_si(temp, ek->lf.f[i]);
				element_mul(fs, temp, as[i].sshares[j][k]);
				element_add(bigSum, bigSum, fs);
			}
			element_set(asReturn->sshares[j][k], bigSum);
		}
	}
}


/**
*  Checks if FunctionVerify holds
*
*  @param 	*vk 		 - A VerificationKey
*  @param 	*as 		 - An AuthAndShare object
*  @param 	*CK 		 - A CommitmentKey
*  @param 	*dataset 	 - An arbitrary long dataset
*  @param 	datasetBytes - The amount of bytes dataset holds
*
*  @return 	1 if FunctionVerify returns 1, 0 otherwise
*/
int Verify(struct VerificationKey *vk, struct AuthAndShare *as, struct CommitmentKey *CK, const unsigned char *dataset, int datasetBytes)
{
	signed long int subset[t];
	// Choose a subset randomly
	for (int i = 0; i < t; i++)
	{
		subset[i] = i;
	}

	element_t r;
	element_init_Zr(r, CK->bm->pairing);
	Reconstruct(subset, as->sshares[0], &r, CK);
	element_t m[T];

	for (int i = 0; i < T; i++)
	{
		element_init_Zr(m[i], CK->bm->pairing);
	}

	for (int i = 1; i <= T; i++)
	{
		Reconstruct(subset, as->sshares[i], &(m[i-1]), CK);
	}

	element_t pubCommit;
	element_init_G1(pubCommit, CK->bm->pairing);
	PublicCommit(CK, m, r, &pubCommit);

	return FunctionVerify(*(vk->pk), *(as->auth), pubCommit, vk->fc, dataset, datasetBytes, CK);
}