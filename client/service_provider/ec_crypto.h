#ifndef ECCRYPTO_H
#define ECCRYPTO_H

#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/oids.h>
#include <cryptopp/pem.h>
#include "cryptopp/files.h"


#define ECC_ALGORITHM ECP
#define ECC_CURVE ASN1::brainpoolP160r1()

void ecdsa_kgen(std::string pk_path, std::string sk_path) {

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PrivateKey sk;
    sk.Initialize(prng, CryptoPP::ECC_CURVE);
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PublicKey pk;
    sk.MakePublicKey(pk);

    CryptoPP::FileSink fs_pri(sk_path.c_str(), true);
    PEM_Save(fs_pri, sk);
    CryptoPP::FileSink fs_pub(pk_path.c_str(), true);
    PEM_Save(fs_pub, pk);
}

void ecc_kgen(std::string pk_path, std::string sk_path) {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PrivateKey privateKey;
    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PublicKey publicKey;
    privateKey.Initialize(prng, CryptoPP::ECC_CURVE);
    privateKey.MakePublicKey(publicKey);

    CryptoPP::FileSink fs_pri(sk_path.c_str(), true);
    PEM_Save(fs_pri, privateKey);
    CryptoPP::FileSink fs_pub(pk_path.c_str(), true);
    PEM_Save(fs_pub, publicKey);
}

void ecdsa_sign(std::vector<uint8_t> &msg, std::vector<uint8_t> &sig, std::string sk_path) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PrivateKey sk;
    CryptoPP::FileSource fs_pri(sk_path.c_str(), true);
    PEM_Load(fs_pri, sk);
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::Signer signer(sk);

    int siglen;
    sig.resize(signer.SignatureLength());
    siglen = signer.SignMessage(prng, msg.data(), msg.size(), sig.data());
    sig.resize(siglen);
}

void ecc_encrypt(std::vector<uint8_t> &msg, std::vector<uint8_t> &ct, std::string pk_path) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PublicKey pk;

    CryptoPP::FileSource fs_pri(pk_path.c_str(), true);
    PEM_Load(fs_pri, pk);

    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::Encryptor encryptor(pk);

    ct.resize(1024);
    encryptor.Encrypt(prng, msg.data(), msg.size(), ct.data());
    int ct_len = encryptor.CiphertextLength(msg.size());
    ct.resize(ct_len);
}

bool ecdsa_verify(std::vector<uint8_t> &msg, std::vector<uint8_t> &sig, std::string vk_path) {
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PublicKey vk;
    CryptoPP::FileSource fs_pub(vk_path.c_str(), true);
    PEM_Load(fs_pub, vk);
    CryptoPP::ECDSA<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::Verifier verifier(vk);

    bool result = verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());

    return result;
}

void ecc_decrypt(std::vector<uint8_t> &msg, std::vector<uint8_t> &ct, std::string sk_path) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::PrivateKey sk;
    CryptoPP::FileSource fs_pri(sk_path.c_str(), true);
    PEM_Load(fs_pri, sk);
    CryptoPP::ECIES<CryptoPP::ECC_ALGORITHM, CryptoPP::SHA256>::Decryptor decryptor(sk);

    int msg_len = decryptor.MaxPlaintextLength(ct.size());
    msg.resize(msg_len);
    decryptor.Decrypt(prng, ct.data(), ct.size(), msg.data());
}


#endif //ECCRYPTO_H
