#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

struct SymmetricCipher {
    using Key = SecByteBlock; // Symmetric key

    static Key Gen(int keySize) {
        AutoSeededRandomPool prng;
        Key key;
        key.resize(keySize / 8);
        prng.GenerateBlock(key.data(), key.size());
        return key;
    }

    static std::string Enc(const Key& key, const std::string& plaintext) {
        AutoSeededRandomPool prng;
        byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        AES::Encryption aesEncryption(key.data(), key.size());
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

        std::string ciphertext;
        StringSource(plaintext, true,
            new StreamTransformationFilter(cbcEncryption,
                new StringSink(ciphertext)
            )
        );

        return ciphertext;
    }

    static std::string Dec(const Key& key, const std::string& ciphertext) {
        AutoSeededRandomPool prng;
        byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));

        AES::Decryption aesDecryption(key.data(), key.size());
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

        std::string plaintext;
        StringSource(ciphertext, true,
            new StreamTransformationFilter(cbcDecryption,
                new StringSink(plaintext)
            )
        );

        return plaintext;
    }
};
