#include <cryptopp/dsa.h>

using namespace CryptoPP;

struct SignatureScheme {
    using PrivateKey = DSA::PrivateKey;
    using PublicKey = DSA::PublicKey;

    static std::pair<PrivateKey, PublicKey> Gen() {
        AutoSeededRandomPool rng;
        DSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 2048);

        DSA::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        return std::make_pair(privateKey, publicKey);
    }

    static std::string sign(const PrivateKey& sk, const std::string& message) {
        AutoSeededRandomPool rng;
        DSA::Signer signer(sk);

        std::string signature;
        StringSource(message, true,
            new SignerFilter(rng, signer,
                new StringSink(signature)
            )
        );

        return signature;
    }

    static bool ver(const PublicKey& pk, const std::string& message, const std::string& signature) {
        DSA::Verifier verifier(pk);

        return verifier.VerifyMessage((const byte*)message.data(), message.size(),
            (const byte*)signature.data(), signature.size());
    }
};
