#include <seal/seal.h>

using namespace seal;

struct HomomorphicEncryption {
    static std::tuple<PublicKey, SecretKey, EvaluationKeys> KeyGen() {
        EncryptionParameters parms(scheme_type::BFV);
        // Set parameters as needed

        SEALContext context(parms);

        KeyGenerator keygen(context);
        PublicKey public_key = keygen.public_key();
        SecretKey secret_key = keygen.secret_key();
        EvaluationKeys ev_keys;
        keygen.generate_evaluation_keys(16, ev_keys);

        return std::make_tuple(public_key, secret_key, ev_keys);
    }

    static Ciphertext Enc(const PublicKey& pk, const Plaintext& m) {
        Encryptor encryptor(pk);
        Ciphertext c;
        encryptor.encrypt(m, c);
        return c;
    }

    static Plaintext Dec(const SecretKey& sk, const Ciphertext& c) {
        Decryptor decryptor(sk);
        Plaintext m;
        decryptor.decrypt(c, m);
        return m;
    }

    static Ciphertext Eval(const EvaluationKeys& evk, const Ciphertext& c1, const Ciphertext& c2) {
        Evaluator evaluator;
        Ciphertext result;
        evaluator.multiply(c1, c2, result);
        evaluator.relinearize_inplace(result, evk);
        return result;
    }
};
