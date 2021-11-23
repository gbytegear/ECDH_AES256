#ifndef SECURITY_HPP
#define SECURITY_HPP

#include <openssl/ecdh.h>
#include "byte_array.hpp"

namespace security {

/**
 * @brief AES256 key and initialization vector
 */
struct AES_t {
  uint8_t key[32] = {
    0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,
    0,0
  };
  uint8_t init_vector[16] = {
    0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0
  };
  bool isEmpty() const {
      static const AES_t empty_aes;
      return !std::memcmp(this, &empty_aes, sizeof (AES_t));
  }
  void clear() {*this = AES_t();}
  AES_t() = default;
  AES_t(ByteArray data) {
    *this = *reinterpret_cast<AES_t*>(data.begin());
  }
};

// ECDH
/**
 * @brief Generate ECDH key pair
 * @return ECDH key pair
 */
EVP_PKEY* genKey();

/**
 * @brief Free key memory
 * @param key
 */
void freeKey(EVP_PKEY* key);

/**
 * @brief Extract public key from key pair
 * @param key_pair
 * @return ByteArray with public key
 */
ByteArray extractPublicKey(EVP_PKEY* key_pair);

/**
 * @brief Extract private key from key pair
 * @param key_pair
 * @return ByteArray with private key
 */
ByteArray extractPrivateKey(EVP_PKEY* key_pair);

/**
 * @brief Conver ByteArrays to key pair
 * @param priv_key_raw
 * @param pub_key_raw
 * @return ECDH key pair
 */
EVP_PKEY* getKeyPair(ByteArray priv_key_raw, ByteArray pub_key_raw);

/**
 * @brief Get AES256 key and initialization vector from ECDH keys
 * @param peer_key - public key from other side
 * @param key_pair - private key from this side
 * @return AES256 key and initialization vector
 */
AES_t getSecret(ByteArray peer_key, EVP_PKEY* key_pair);

// AES256
/**
 * @brief Encrypt message
 * @param plain_text
 * @param aes_struct
 * @return Cyphertext
 */
ByteArray encrypt(ByteArray plain_text, AES_t aes_struct);

/**
 * @brief Decrypt message
 * @param ciphertext
 * @param aes_struct
 * @return plain_text
 */
ByteArray decrypt(ByteArray ciphertext, AES_t aes_struct);

/**
* @brief Encode data with base64
* @param decoded
* @return
*/
ByteArray encodeBase64(ByteArray decoded);

/**
* @brief Decode base64 data
* @param encoded
* @return
*/
ByteArray decodeBase64(ByteArray encoded);

}

#endif // SECURITY_HPP
