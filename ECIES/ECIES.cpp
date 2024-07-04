#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <iostream>
#include <vector>
#include <cstring>

// Function to handle OpenSSL errors
void handleOpenSSLError() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate an ECC key pair
EVP_PKEY* generateKey() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) handleOpenSSLError();
    // Set the curve to NID_X9_62_prime256v1 (secp256r1)
    if (EVP_PKEY_keygen_init(pctx) <= 0) handleOpenSSLError();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) handleOpenSSLError();

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handleOpenSSLError();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

// Derive a shared secret using ECDH
std::vector<unsigned char> deriveSharedSecret(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx) handleOpenSSLError();

    if (EVP_PKEY_derive_init(ctx) <= 0) handleOpenSSLError();
    if (EVP_PKEY_derive_set_peer(ctx, peerPublicKey) <= 0) handleOpenSSLError();

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) handleOpenSSLError();

    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) handleOpenSSLError();

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

// Encrypt data using the shared secret
std::vector<unsigned char> encryptWithAES(const std::vector<unsigned char>& sharedSecret, const std::vector<unsigned char>& plaintext) {
    // Use the shared secret as a key for AES encryption
    std::vector<unsigned char> key(sharedSecret.begin(), sharedSecret.begin() + 32);

    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) handleOpenSSLError();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleOpenSSLError();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) handleOpenSSLError();

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) handleOpenSSLError();
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) handleOpenSSLError();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());

    return ciphertext;
}

// Decrypt data using the shared secret
std::vector<unsigned char> decryptWithAES(const std::vector<unsigned char>& sharedSecret, const std::vector<unsigned char>& ciphertext) {
    // Use the shared secret as a key for AES decryption
    std::vector<unsigned char> key(sharedSecret.begin(), sharedSecret.begin() + 32);

    std::vector<unsigned char> iv(ciphertext.end() - AES_BLOCK_SIZE, ciphertext.end());
    std::vector<unsigned char> actual_ciphertext(ciphertext.begin(), ciphertext.end() - AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleOpenSSLError();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) handleOpenSSLError();

    std::vector<unsigned char> plaintext(actual_ciphertext.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext.data(), actual_ciphertext.size()) != 1) handleOpenSSLError();
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) handleOpenSSLError();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);

    return plaintext;
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate ECC key pairs
    EVP_PKEY* peerkey1 = generateKey();
    if (!peerkey1) handleOpenSSLError();

    EVP_PKEY* peerKey2 = generateKey();
    if (!peerKey2) handleOpenSSLError();

    // Derive shared secret using ECDH
    std::vector<unsigned char> sharedSecret = deriveSharedSecret(peerkey1, peerKey2);

    // Prompt the user for input
    std::string inputMessage;
    std::cout << "Please input the plain text to be encrypted: ";
    std::getline(std::cin, inputMessage);

    // Convert the input string to a vector of unsigned chars
    std::vector<unsigned char> message(inputMessage.begin(), inputMessage.end());

    // Encrypt the message using the shared secret
    std::vector<unsigned char> encryptedMessage = encryptWithAES(sharedSecret, message);
    std::cout << "Encrypted message: ";
    for (unsigned char c : encryptedMessage) {
        std::cout << std::hex << static_cast<int>(c);
    }
    std::cout << std::endl;

    // Decrypt the message using the shared secret
    std::vector<unsigned char> decryptedMessage = decryptWithAES(sharedSecret, encryptedMessage);
    std::cout << "Decrypted message: ";
    for (unsigned char c : decryptedMessage) {
        std::cout << c;
    }
    std::cout << std::endl;

    // Cleanup
    EVP_PKEY_free(peerkey1);
    EVP_PKEY_free(peerKey2);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
