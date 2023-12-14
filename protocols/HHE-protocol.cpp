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
    vector<int64_t> w{10, 29, 13, 19}; // weights
    vector<int64_t> b{-3, -3, -3, -3}; // biases
    Ciphertext w_c; // encrypted weights
    Ciphertext b_c; // encrypted biases
    PublicKey analyst_pk; // HE public key
    SecretKey analyst_sk; // HE secret key
    RelinKeys analyst_rk; 
    GaloisKeys analyst_gk;   
};

struct CSP
{
    std::vector<Ciphertext> c_prime; // HE encrypted user's data c
    std::vector<Ciphertext> c_res; // evaluation result
    SecretKey csp_sk;
};

int main()
{
    User User;
    Analyst Analyst;
    CSP CSP;
    chrono::high_resolution_clock::time_point st1, st2, st3, st4, st5, st6, end1, end2, end3, end4, end5, end6;
    chrono::milliseconds diff1, diff2, diff3, diff4, diff5, diff6;

    // SD Setup
    cout << "SD.Setup" << endl;
    cout << "Analyst creates the context" << endl;
    shared_ptr<SEALContext> context = get_seal_context(65537, 16384, 128);
    print_parameters(*context);

    cout << "Analyst creates keys, encryptor and evaluator" << endl;
    st1 = chrono::high_resolution_clock::now(); // Start time
    KeyGenerator keygen(*context);
    Analyst.analyst_sk = keygen.secret_key(); 
    keygen.create_public_key(Analyst.analyst_pk);
    keygen.create_relin_keys(Analyst.analyst_rk);
    BatchEncoder analyst_batch(*context);
    vector<int> gk_indices = add_gk_indices(false, analyst_batch);
    keygen.create_galois_keys(gk_indices, Analyst.analyst_gk);
    Encryptor analyst_enc(*context, Analyst.analyst_pk);
    Evaluator analyst_eval(*context);
    end1 = chrono::high_resolution_clock::now(); // Stop time
    diff1 = chrono::duration_cast<chrono::milliseconds>(end1-st1);
    cout << "Time to create HE keys for analyst: " << diff1.count() << endl;

    // Analyst encrypts weights and biases" 
    Analyst.w_c = encrypting(Analyst.w, Analyst.he_pk, analyst_batch, analyst_enc);
    Analyst.b_c = encrypting(Analyst.b, Analyst.he_pk, analyst_batch, analyst_enc);

    cout << "User creates a symmetric key" << endl;
    User.k = get_symmetric_key();

    cout << "CSP creates a secret key" << endl;
    KeyGenerator csp_keygen(*context);
    CSP.csp_sk = csp_keygen.secret_key();

    cout << "Analyst sends its evaluation key to CSP (creates m_1)" << endl;


    // SD Add
    cout << "SD.Add" << endl;
    print_vec(User.x, User.x.size(), "User's data to send");

    cout << "User encrypts their data using the symmetric key" << endl;
    st3 = chrono::high_resolution_clock::now(); // Start time
    PASTA_3::PASTA SymmetricEncryptor(User.k, 65537);
    User.c = SymmetricEncryptor.encrypt(User.x);
    end3 = chrono::high_resolution_clock::now(); // Stop time
    diff3 = chrono::duration_cast<chrono::milliseconds>(end3-st3);
    print_vec(User.c, User.c.size(), "User's encrypted data'");
    cout << "Time to encrypt user's symmetric key: " << diff3.count() << endl;

    cout << "User homomorphically encrypts their symmetric key under analyst's public key" << endl;
    st2 = chrono::high_resolution_clock::now(); // Start time
    User.c_k = encrypt_symmetric_key(User.k, true, analyst_batch, analyst_enc);
    end2 = chrono::high_resolution_clock::now(); // Stop time
    diff2 = chrono::duration_cast<chrono::milliseconds>(end2-st2);
    cout << "Time to encrypt user's symmetric key: " << diff2.count() << endl;


    cout << "User sends its data and encrypted key to CSP (creates m_2)" << endl;

    cout << "CSP transforms the symmetric ciphertext (received data) to a homomorphic one" << endl;
    st4 = chrono::high_resolution_clock::now(); // Start time
    PASTA_3::PASTA_SEAL CSPWorker(context, Analyst.analyst_pk, CSP.csp_sk, Analyst.analyst_rk, Analyst.analyst_gk);
    CSP.c_prime = CSPWorker.decomposition(User.c, User.c_k, true);
    end4 = chrono::high_resolution_clock::now(); // Stop time
    diff4 = chrono::duration_cast<chrono::milliseconds>(end4-st4);
    cout << "Time to decomposition: " << diff4.count() << endl;


    // SD Query
    cout << "SD.Query" << endl;
    cout << "Analyst sends a query to CSP (creates m_3)" << endl;

    cout << "CSP evaluates a linear transformation to the data" << endl;
    st5 = chrono::high_resolution_clock::now(); // Start time
    packed_enc_multiply(CSP.c_prime[0], Analyst.w_c, CSP.c_res[0], analyst_eval);
    packed_enc_addition(CSP.c_res[0], Analyst.b_c, CSP.c_res[0], analyst_eval);
    end5 = chrono::high_resolution_clock::now(); // Stop time
    diff5 = chrono::duration_cast<chrono::milliseconds>(end5-st5);
    cout << "Time to evaluate (multiply + addition): " << diff5.count() << endl;

    cout << "CSP sends the evaluated data back (creates m_4)" << endl;


    cout << "Analyst decrypts the data" << endl;
    vector<int64_t> result;
    st6 = chrono::high_resolution_clock::now(); // Start time
    result = decrypting(CSP.c_res, Analyst.analyst_sk, analyst_batch, *context, Analyst.w.size());
    end6 = chrono::high_resolution_clock::now(); // Stop time
    diff6 = chrono::duration_cast<chrono::milliseconds>(end6-st6);
    print_vec(result, result.size(), "Result");
    cout << "Time to decrypt: " << diff6.count() << endl;

    return 0;
}   