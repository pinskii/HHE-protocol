#include "seal/seal.h"

using namespace seal;

struct HomomorphicEncryption {
    static EncryptionParameters GenerateContext(size_t modulus) {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(modulus);
	    parms.set_coeff_modulus(CoeffModulus::BFVDefault(modulus));
	    parms.set_plain_modulus(PlainModulus::Batching(modulus, 20));

        return parms;
    }

    static std::tuple<PublicKey, SecretKey, RelinKeys> KeyGen(SEALContext context) {
        KeyGenerator keygen(context);
        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        return std::make_tuple(public_key, secret_key, relin_keys);
    }

    static Ciphertext Enc(const PublicKey& pk, const Plaintext& m, SEALContext context) {
        Encryptor encryptor(context, pk);
        Ciphertext c;
        encryptor.encrypt(m, c);
        return c;
    }

    static Plaintext Dec(const SecretKey& sk, const Ciphertext& c, SEALContext context) {
        Decryptor decryptor(context, sk);
        Plaintext m;
        decryptor.decrypt(c, m);
        return m;
    }

    static Ciphertext Eval(const Ciphertext& c1, const Ciphertext& c2, const RelinKeys& rk, SEALContext context) {
        Evaluator evaluator = Evaluator(context);
        Ciphertext result;
        evaluator.multiply(c1, c2, result);
        evaluator.relinearize_inplace(result, rk);
        return result;
    }
};
