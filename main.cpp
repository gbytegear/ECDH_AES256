#include "security.hpp"
#include <iostream>

int main([[maybe_unused]]int argc, [[maybe_unused]]char* argv[]) {
  using namespace security;
  EVP_PKEY* alice_key_pair = genKey();
  ByteArray alice_peer_key = extractPublicKey(alice_key_pair);

  EVP_PKEY* bob_key_pair = genKey();
  ByteArray bob_peer_key = extractPublicKey(bob_key_pair);

  AES_t bob_aes_key = getSecret(alice_peer_key, bob_key_pair);

  AES_t alice_aes_key = getSecret(bob_peer_key, alice_key_pair);

  std::string alice_msg = "Hello, Bob";
  ByteArray alice_msg_buffer(alice_msg.data(), alice_msg.length() + 1);
  ByteArray alice_enc_msg = encrypt(alice_msg_buffer, alice_aes_key);

  std::string bob_msg = "Hello, Alice";
  ByteArray bob_msg_buffer(bob_msg.data(), bob_msg.length() + 1);
  ByteArray bob_enc_msg = encrypt(bob_msg_buffer, bob_aes_key);

  ByteArray alice_recived_msg = decrypt(bob_enc_msg, alice_aes_key);
  std::cout << "Bob: " << (char*)alice_recived_msg.begin() << '\n';

  ByteArray bob_recived_msg = decrypt(alice_enc_msg, bob_aes_key);
  std::cout << "Alice: " << (char*)bob_recived_msg.begin() << '\n';

  return 0;
}
