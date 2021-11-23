#include "security.hpp"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// AES
#include <openssl/aes.h>
// ECDH
#include <openssl/ec.h>
#include <openssl/pem.h>

#include <stdexcept>

void handleErrors() {
  ERR_print_errors_fp(stderr);
  throw std::runtime_error("Security error");
}

EVP_PKEY* security::genKey() {
  EVP_PKEY* key_pair = nullptr;
  EVP_PKEY_CTX* param_gen_ctx = nullptr;
  EVP_PKEY_CTX* key_gen_ctx = nullptr;
  EVP_PKEY* params= nullptr;

  if(!(param_gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();
  if(!EVP_PKEY_paramgen_init(param_gen_ctx)) handleErrors();

  if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_gen_ctx, NID_X9_62_prime256v1))
    handleErrors();

  if(!EVP_PKEY_paramgen(param_gen_ctx, &params)) handleErrors();

  if(!(key_gen_ctx = EVP_PKEY_CTX_new(params, nullptr))) handleErrors();
  if(!EVP_PKEY_keygen_init(key_gen_ctx)) handleErrors();
  if(!EVP_PKEY_keygen(key_gen_ctx, &key_pair)) handleErrors();

  EVP_PKEY_CTX_free(param_gen_ctx);
  EVP_PKEY_CTX_free(key_gen_ctx);
  return key_pair;
}

void security::freeKey(EVP_PKEY* key) {EVP_PKEY_free(key);}

ByteArray security::extractPublicKey(EVP_PKEY* key_pair) {
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key_pair);
    EC_POINT* ec_point = const_cast<EC_POINT*>(EC_KEY_get0_public_key(ec_key));

    EVP_PKEY* public_key = EVP_PKEY_new();
    EC_KEY* public_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    EC_KEY_set_public_key(public_ec_key, ec_point);
    EVP_PKEY_set1_EC_KEY(public_key, public_ec_key);


    EC_KEY *temp_ec_key = EVP_PKEY_get0_EC_KEY(public_key);

    if(temp_ec_key == NULL) handleErrors();

    const EC_GROUP* group = EC_KEY_get0_group(temp_ec_key);
    point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);

    unsigned char* pub_key_buffer;
    size_t length = EC_KEY_key2buf(temp_ec_key, form, &pub_key_buffer, NULL);
    if(!length) handleErrors();
    ByteArray data(pub_key_buffer, length);

    OPENSSL_free(pub_key_buffer);
    EVP_PKEY_free(public_key);
    EC_KEY_free(ec_key);
    EC_KEY_free(public_ec_key);
    EC_POINT_free(ec_point);

    return data;
}

ByteArray security::extractPrivateKey(EVP_PKEY* key_pair) {
  EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key_pair);
  const BIGNUM* ec_priv = EC_KEY_get0_private_key(ec_key);
  int length = BN_bn2mpi(ec_priv, nullptr);
  ByteArray data(length);
  BN_bn2mpi(ec_priv, data.begin());
  return data;
}

EVP_PKEY* security::getKeyPair(ByteArray priv_key_raw, ByteArray pub_key_raw) {
  EVP_PKEY* key_pair = EVP_PKEY_new();
  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
  EC_POINT* ec_point = EC_POINT_new(ec_group);
  EC_POINT_oct2point(ec_group, ec_point, pub_key_raw.begin(), pub_key_raw.length(), nullptr);
  EC_KEY_set_public_key(ec_key, ec_point);
  EC_POINT_free(ec_point);

  BIGNUM* priv = BN_mpi2bn(priv_key_raw.begin(), priv_key_raw.length(), nullptr);
  EC_KEY_set_private_key(ec_key, priv);
  BN_free(priv);

  EVP_PKEY_set1_EC_KEY(key_pair, ec_key);
  EC_KEY_free(ec_key);
  return key_pair;
}

security::AES_t security::getSecret(ByteArray peer_key, EVP_PKEY* key_pair) {
  EC_KEY *temp_ec_key = nullptr;
  EVP_PKEY *peerkey = nullptr;

  temp_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(temp_ec_key == nullptr)
    handleErrors();
  if(EC_KEY_oct2key(temp_ec_key, peer_key.begin(), peer_key.length(), NULL) != 1)
    handleErrors();
  if(EC_KEY_check_key(temp_ec_key) != 1) handleErrors();
  peerkey = EVP_PKEY_new();
  if(peerkey == NULL)
    handleErrors();
  if(EVP_PKEY_assign_EC_KEY(peerkey, temp_ec_key)!= 1)
    handleErrors();

  EVP_PKEY_CTX *derivation_ctx = EVP_PKEY_CTX_new(key_pair, NULL);
  EVP_PKEY_derive_init(derivation_ctx);
  EVP_PKEY_derive_set_peer(derivation_ctx, peerkey);
  size_t lenght;
  void* ptr;
  if(1 != EVP_PKEY_derive(derivation_ctx, NULL, &lenght)) handleErrors();
  if(NULL == (ptr = OPENSSL_malloc(lenght))) handleErrors();
  if(1 != (EVP_PKEY_derive(derivation_ctx, (unsigned char*)ptr, &lenght))) handleErrors();
  EVP_PKEY_CTX_free(derivation_ctx);
  EVP_PKEY_free(peerkey);

  AES_t aes_key;
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL)
    handleErrors();
  if(1 != EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL))
    handleErrors();
  if(1 != EVP_DigestUpdate(mdctx, ptr, lenght))
    handleErrors();
  unsigned int length;
  if(1 != EVP_DigestFinal_ex(mdctx, (unsigned char*)&aes_key, &length))
    handleErrors();
  EVP_MD_CTX_free(mdctx);
  OPENSSL_free(ptr);
  return aes_key;
}

ByteArray security::encrypt(ByteArray plain_text, security::AES_t aes_struct) {
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  ByteArray ciphertext(plain_text.length() % AES_BLOCK_SIZE == 0
                       ? plain_text.length()
                       : (plain_text.length() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE);

  EVP_CIPHER_CTX *ctx;
  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_struct.key, aes_struct.init_vector))
    handleErrors();

  int f_length, s_length;
  if(1 != EVP_EncryptUpdate(ctx, ciphertext.begin(), &f_length, plain_text.begin(), plain_text.length()))
    handleErrors();

  if(uint64_t(f_length) == ciphertext.length())
    ciphertext.addSize(16);
  else if(uint64_t(f_length) > ciphertext.length())
      throw std::runtime_error("Predicted ciphertext size lower then actual!");

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext.begin() + f_length, &s_length))
    handleErrors();
  if(uint64_t reuired_length = f_length + s_length;reuired_length < ciphertext.length())
    ciphertext.resize(f_length + s_length);
  else if(reuired_length > ciphertext.length())
      throw std::runtime_error("Predicted ciphertext size lower then actual!");

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext;
}

ByteArray security::decrypt(ByteArray ciphertext, security::AES_t aes_struct) {
  EVP_CIPHER_CTX *ctx;
  ByteArray plain_text(ciphertext.length());

  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_struct.key, aes_struct.init_vector))
    handleErrors();

  int f_length, s_length;
  if(1 != EVP_DecryptUpdate(ctx, plain_text.begin(), &f_length, ciphertext.begin(), ciphertext.length()))
    handleErrors();

  if(1 != EVP_DecryptFinal_ex(ctx, plain_text.begin() + f_length, &s_length))
    handleErrors();
  plain_text.resize(f_length + s_length);

  EVP_CIPHER_CTX_free(ctx);

  return plain_text;
}

ByteArray security::encodeBase64(ByteArray decoded) {
  ByteArray encoded((4*((decoded.length()+2)/3)) + 1);
  EVP_EncodeBlock(encoded.begin(), decoded.begin(), decoded.length());
  return encoded;
}

ByteArray security::decodeBase64(ByteArray encoded) {
  ByteArray decoded((3*encoded.length()/4) + 1);
  size_t recived_data_size = EVP_DecodeBlock(decoded.begin(), encoded.begin(), encoded.length());
  if(recived_data_size < decoded.length())
    decoded.resize(recived_data_size);
  return decoded;
}
