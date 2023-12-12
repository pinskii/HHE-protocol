// TODO: includes

struct HybridHomomorphicEncryption {
    static std::tuple<PublicKey, SecretKey, EvaluationKeys> KeyGen(int lambda) {
        return HomomorphicEncryption::KeyGen(lambda);
    }

    static std::tuple<Ciphertext, Ciphertext> Enc(const PublicKey& pk, const SymmetricKey& K, const Plaintext& m) {
        Ciphertext cK = HomomorphicEncryption::Enc(pk, K);
        Ciphertext c = SymmetricKeyEncryption::Enc(K, m);
        return std::make_tuple(cK, c);
    }

    static Ciphertext Decomp(const EvaluationKeys& evk, const Ciphertext& c, const Ciphertext& cK) {
        Ciphertext c_prime = HomomorphicEncryption::Eval(evk, cK, c);
        return c_prime;
    }

    static Ciphertext Eval(const EvaluationKeys& evk, const Ciphertext& c1, const Ciphertext& c2) {
        return HomomorphicEncryption::Eval(evk, c1, c2);
    }

    static Plaintext Dec(const SecretKey& sk, const Ciphertext& c_prime) {
        return HomomorphicEncryption::Dec(sk, c_prime);
    }
};