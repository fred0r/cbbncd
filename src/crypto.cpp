#include "crypto.h"

#include <climits>
#include <cstring>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LENGTH 8
#define SALT_STRING_LENGTH 16
#define LEGACY_DEFAULT_ITER 10000
#define NEW_KDF_ITER 600000
#define NEW_SALT_LENGTH 32
#define NEW_IV_LENGTH 12
#define NEW_GCM_TAG_LENGTH 16
#define FORMAT_VERSION 0x01

namespace {

const EVP_MD * digest() {
  return EVP_sha256();
}

unsigned char hex2uc(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (tolower(c) >= 'a' && tolower(c) <= 'f') {
    return c - 'W';
  }
  return 0;
}

std::string uc2hex(unsigned char c) {
  std::string out;
  char major = c / 16;
  out += major >= 10 ? major + 'W' : major + '0';
  char minor = c % 16;
  out += minor >= 10 ? minor + 'W' : minor + '0';
  return out;
}

}

void Crypto::encrypt(const Core::BinaryData & indata, const Core::BinaryData & pass, Core::BinaryData & outdata) {
  if (indata.empty()) {
    outdata.resize(0);
    return;
  }

  unsigned char salt[NEW_SALT_LENGTH];
  if (RAND_bytes(salt, sizeof(salt)) != 1) {
    outdata.resize(0);
    return;
  }

  unsigned char iv[NEW_IV_LENGTH];
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    outdata.resize(0);
    return;
  }

  unsigned char key[32];
  PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(pass.data()), pass.size(),
                     salt, sizeof(salt), NEW_KDF_ITER, digest(), sizeof(key), key);

  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    outdata.resize(0);
    return;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  size_t header_size = 1 + 4 + sizeof(salt) + sizeof(iv);
  outdata.resize(header_size + indata.size() + NEW_GCM_TAG_LENGTH);

  outdata[0] = FORMAT_VERSION;
  uint32_t saltlen_net = htonl(sizeof(salt));
  memcpy(&outdata[1], &saltlen_net, 4);
  memcpy(&outdata[5], salt, sizeof(salt));
  memcpy(&outdata[5 + sizeof(salt)], iv, sizeof(iv));

  int outlen = 0;
  if (EVP_EncryptUpdate(ctx, &outdata[header_size], &outlen, indata.data(), indata.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  int finallen = 0;
  if (EVP_EncryptFinal_ex(ctx, &outdata[header_size + outlen], &finallen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  unsigned char tag[NEW_GCM_TAG_LENGTH];
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  size_t ciphertext_len = outlen + finallen;
  memcpy(&outdata[header_size + ciphertext_len], tag, sizeof(tag));
  outdata.resize(header_size + ciphertext_len + sizeof(tag));

  EVP_CIPHER_CTX_free(ctx);
}

void Crypto::decrypt(const Core::BinaryData & indata, const Core::BinaryData & pass, Core::BinaryData & outdata) {
  if (indata.empty()) {
    outdata.resize(0);
    return;
  }

  if (indata.size() >= 8 && memcmp(&indata[0], "Salted__", 8) == 0) {
    decryptLegacy(indata, pass, outdata);
    return;
  }

  if (indata.size() < 1 || indata[0] != FORMAT_VERSION) {
    outdata.resize(0);
    return;
  }

  size_t pos = 1;

  if (indata.size() < pos + 4) {
    outdata.resize(0);
    return;
  }
  uint32_t saltlen_net;
  memcpy(&saltlen_net, &indata[pos], 4);
  uint32_t saltlen = ntohl(saltlen_net);
  pos += 4;

  if (indata.size() < pos + saltlen) {
    outdata.resize(0);
    return;
  }
  const unsigned char * salt = &indata[pos];
  pos += saltlen;

  if (indata.size() < pos + NEW_IV_LENGTH) {
    outdata.resize(0);
    return;
  }
  unsigned char iv[NEW_IV_LENGTH];
  memcpy(iv, &indata[pos], sizeof(iv));
  pos += sizeof(iv);

  if (indata.size() < pos + NEW_GCM_TAG_LENGTH) {
    outdata.resize(0);
    return;
  }
  size_t ciphertext_len = indata.size() - pos - NEW_GCM_TAG_LENGTH;

  unsigned char key[32];
  PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(pass.data()), pass.size(),
                     salt, saltlen, NEW_KDF_ITER, digest(), sizeof(key), key);

  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    outdata.resize(0);
    return;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  outdata.resize(ciphertext_len);
  int outlen = 0;
  if (EVP_DecryptUpdate(ctx, outdata.data(), &outlen, &indata[pos], ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, NEW_GCM_TAG_LENGTH,
                          const_cast<unsigned char *>(&indata[pos + ciphertext_len])) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  int finallen = 0;
  if (EVP_DecryptFinal_ex(ctx, outdata.data() + outlen, &finallen) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    outdata.resize(0);
    return;
  }

  outdata.resize(outlen + finallen);
  EVP_CIPHER_CTX_free(ctx);
}

void Crypto::decryptLegacy(const Core::BinaryData & indata, const Core::BinaryData & pass, Core::BinaryData & outdata) {
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER * cipherp = EVP_aes_256_cbc();

  int keylen = EVP_CIPHER_key_length(cipherp);
  unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
  unsigned char* key = tmpkeyiv;
  unsigned char* iv = tmpkeyiv + keylen;
#if OPENSSL_VERSION_NUMBER < 0x10000000L
  EVP_BytesToKey(cipherp, digest(), &indata[SALT_STRING_LENGTH - SALT_LENGTH], !pass.empty() ? pass.data() : NULL,
                 pass.size(), 1, key, iv);
#else
  int ivlen = EVP_CIPHER_iv_length(cipherp);
  PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(pass.data()), pass.size(),
                    &indata[SALT_STRING_LENGTH - SALT_LENGTH], SALT_LENGTH,
                    LEGACY_DEFAULT_ITER, digest(), keylen + ivlen, tmpkeyiv);
#endif
  outdata.resize(indata.size() + EVP_CIPHER_block_size(cipherp));
  int writelen;
  int finalwritelen;
  EVP_DecryptInit_ex(ctx, cipherp, NULL, key, iv);
  EVP_DecryptUpdate(ctx, &outdata[0], &writelen, &indata[SALT_STRING_LENGTH],
                    indata.size() - SALT_STRING_LENGTH);
  EVP_DecryptFinal_ex(ctx, &outdata[writelen], &finalwritelen);
  outdata.resize(writelen + finalwritelen);
  EVP_CIPHER_CTX_free(ctx);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

void Crypto::sha256(const Core::BinaryData & indata, Core::BinaryData & outdata) {
  if (indata.empty()) {
    outdata.resize(0);
    return;
  }
  outdata.resize(EVP_MD_size(digest()));
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    outdata.resize(0);
    return;
  }
  EVP_DigestInit(ctx, digest());
  EVP_DigestUpdate(ctx, &indata[0], indata.size());
  EVP_DigestFinal(ctx, &outdata[0], nullptr);
  EVP_MD_CTX_free(ctx);
}

void Crypto::base64Encode(const Core::BinaryData & indata, Core::BinaryData & outdata) {
  if (indata.empty()) {
    outdata.resize(0);
    return;
  }
  outdata.resize((indata.size() / 3 + ((indata.size() % 3) ? 1 : 0)) * 4 + 1);
  int bytes = EVP_EncodeBlock(&outdata[0], &indata[0], indata.size());
  outdata.resize(bytes);
}

void Crypto::base64Decode(const Core::BinaryData & indata, Core::BinaryData & outdata) {
  if (indata.empty()) {
    outdata.resize(0);
    return;
  }
  int pos = indata.size();
  int padding = 0;
  while (--pos >= 0 && indata[pos] == '=') {
    ++padding;
  }
  unsigned int outsize = indata.size() / 4 * 3;
  outdata.resize(outsize);
  EVP_DecodeBlock(&outdata[0], &indata[0], indata.size());
  outdata.resize(outsize - padding);
}

bool Crypto::isMostlyASCII(const Core::BinaryData& data) {
  unsigned int asciicount = 0;
  for (unsigned int i = 0; i < data.size(); ++i) {
    if (data[i] < 128) {
      ++asciicount;
    }
  }
  return asciicount > data.size() * 0.9;
}

std::string Crypto::toHex(const Core::BinaryData& indata) {
  std::string out;
  out.reserve(indata.size() * 2);
  for (size_t i = 0; i < indata.size(); ++i) {
    out += uc2hex(indata[i]);
  }
  return out;
}

void Crypto::fromHex(const std::string& indata, Core::BinaryData& outdata) {
  outdata.resize(indata.size() / 2);
  for (size_t i = 0; i < outdata.size(); ++i) {
    outdata[i] = hex2uc(indata[i * 2]) * 16 + hex2uc(indata[i * 2 + 1]);
  }
}