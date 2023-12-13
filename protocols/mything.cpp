#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h"
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"

using namespace std;
using namespace seal;

struct User
{
    vector<uint64_t> k; // secret symmetric keys
    vector<uint64_t> x{0, 1, 2, 3}; // user's data
    vector<uint64_t> c; // encrypted data
    std::vector<Ciphertext> c_k; // encrypted symmetric keys
};

struct Analyst
{
    vector<int64_t> w{17, 31, 24, 17}; // dummy weights
    vector<int64_t> b{-5, -5, -5, -5}; // dummy biases
    Ciphertext w_c;                    // the encrypted weights
    Ciphertext b_c;                    // the encrypted biases
    PublicKey analyst_pk;
    SecretKey analyst_sk;
    RelinKeys analyst_rk;
    GaloisKeys he_gk;
};

struct CSP
{
    std::vector<Ciphertext> c_prime; // the decomposed HE encrypted data of user's c_i
    Ciphertext c_res;                // the HE encrypted results that will be sent to the Analyst
    SecretKey he_sk;
};

int main()
{
    User User;
    Analyst Analyst;
    CSP CSP;


    // SD Setup
    cout << "Analyst creates the context" << endl;
    shared_ptr<SEALContext> context = get_seal_context(65537, 16384, 128);
    print_parameters(*context);
    print_line(__LINE__);

    cout << "SD.Setup" << endl;

    cout << "Analyst creates keys, encryptor and evaluator" << endl;
    KeyGenerator keygen(*context);
    Analyst.analyst_sk = keygen.secret_key(); 
    keygen.create_public_key(Analyst.analyst_pk);
    keygen.create_relin_keys(Analyst.analyst_rk);
    BatchEncoder analyst_he_benc(*context);
    Encryptor analyst_he_enc(*context, Analyst.analyst_pk);
    Evaluator analyst_he_eval(*context);
    print_line(__LINE__);

    cout << "User creates a symmetric key" << endl;
    User.k = get_symmetric_key();

    cout << "CSP creates a secret key" << endl;
    KeyGenerator csp_keygen(*context);
    CSP.he_sk = csp_keygen.secret_key();

    // SD Add
    print_vec(User.x, User.x.size(), "User's data to send");
    print_line(__LINE__);

    cout << "User encrypts their data using the symmetric key" << endl;
    PASTA_3::PASTA SymmetricEncryptor(User.k, 65537);
    User.c = SymmetricEncryptor.encrypt(User.x);
    print_vec(User.c, User.c.size(), "User's encrypted data'");
    print_line(__LINE__);

    cout << "User homomorphically encrypts their symmetric key under analyst's public key" << endl;
    User.c_k = encrypt_symmetric_key(User.k, true, analyst_he_benc, analyst_he_enc);

    cout << "CSP transforms the symmetric ciphertext (received data) to a homomorphic one" << endl;
    CSP.c_prime = PASTA_SEAL::decomposition(User.c, User.k, true);


    // SD Query