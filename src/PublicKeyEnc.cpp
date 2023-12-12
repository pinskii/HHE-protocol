#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

struct PublicKeyEncryption {
    using PublicKey = RSA::PublicKey;
    using PrivateKey = RSA::PrivateKey;

    static std::pair<PublicKey, PrivateKey> Gen() {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 2048);

        RSA::PublicKey publicKey(privateKey);

        return std::make_pair(publicKey, privateKey);
    }

    static std::string Enc(const PublicKey& pk, const std::string& plaintext) {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor encryptor(pk);
        
        std::string ciphertext;
        StringSource(plaintext, true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(ciphertext)
            )
        );

        return ciphertext;
    }

    static std::string Dec(const PrivateKey& sk, const std::string& ciphertext) {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor decryptor(sk);
        
        std::string plaintext;
        StringSource(ciphertext, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(plaintext)
            )
        );

        return plaintext;
    }
};
