#include <vector>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h"
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"
#include "../src/openssl/include/openssl/rsa.h"
#include "../src/openssl/pem.h"

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
    OpenSSL_add_all_algorithms();
    User User;
    Analyst Analyst;
    CSP CSP;
    chrono::high_resolution_clock::time_point st1, st2, st3, end1, end2, end3;
    chrono::milliseconds diff1, diff2, diff3;

    // SD Setup
    cout << "SD.Setup" << endl;
    RSA *keypair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    cout << "Analyst creates the context" << endl;
    shared_ptr<SEALContext> context = get_seal_context(65537, 16384, 128);
    print_parameters(*context);
    print_line(__LINE__);

    cout << "Analyst creates keys, encryptor and evaluator" << endl;
    st1 = chrono::high_resolution_clock::now(); // Start time
    KeyGenerator keygen(*context);
    Analyst.analyst_sk = keygen.secret_key(); 
    keygen.create_public_key(Analyst.analyst_pk);
    keygen.create_relin_keys(Analyst.analyst_rk);
    BatchEncoder analyst_batch(*context);
    Encryptor analyst_enc(*context, Analyst.analyst_pk);
    Evaluator analyst_eval(*context);
    end1 = chrono::high_resolution_clock::now(); // Stop time
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1-st1);
    cout << "Time to create HE keys for analyst: " << diff1.count() << endl;

    cout << "User creates a symmetric key" << endl;
    User.k = get_symmetric_key();

    cout << "CSP creates a secret key" << endl;
    KeyGenerator csp_keygen(*context);
    CSP.he_sk = csp_keygen.secret_key();

    // SD Add
    cout << "SD.Add" << endl;
    print_vec(User.x, User.x.size(), "User's data to send");
    print_line(__LINE__);

    cout << "User encrypts their data using the symmetric key" << endl;
    PASTA_3::PASTA SymmetricEncryptor(User.k, 65537);
    User.c = SymmetricEncryptor.encrypt(User.x);
    print_vec(User.c, User.c.size(), "User's encrypted data'");
    print_line(__LINE__);

    cout << "User homomorphically encrypts their symmetric key under analyst's public key" << endl;
    User.c_k = encrypt_symmetric_key(User.k, true, analyst_batch, analyst_enc);

    cout << "CSP transforms the symmetric ciphertext (received data) to a homomorphic one" << endl;
    PASTA_3::PASTA_SEAL CSPWorker(context, Analyst.analyst_pk, CSP.he_sk, Analyst.analyst_rk, Analyst.he_gk);
    CSP.c_prime = CSPWorker.decomposition(User.c, User.c_k, true);


    // SD Query
}