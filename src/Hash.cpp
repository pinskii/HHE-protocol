#include <cryptopp/sha.h>

using namespace CryptoPP;

struct HashFunction {
    static std::string hash(const std::string& input) {
        SHA256 hash;
        std::string digest;
        
        StringSource(input, true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );

        return digest;
    }
};
