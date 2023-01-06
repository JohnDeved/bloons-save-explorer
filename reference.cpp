#include <fstream>
#include <iostream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/zlib.h"
#include "cryptopp/osrng.h"

#define MONKE_DUMMY_HEADER_LENGTH 44
#define MONKE_SALT_LENGTH 24
#define MONKE_KEY_LENGTH 16
#define MONKE_IV_LENGTH 16
#define MONKE_DERIVE_ITERATIONS 10
#define MONKE_PASSWORD_INDEX 2
#define MONKE_COMPRESSION_LEVEL 3
#define MONKE_COMPRESSION_LOG2_BUFFER_SIZE 11 // 2^11 == 2048

void Pack::unpack(std::string_view input_path, std::string_view output_path, std::string_view password) {
  // open input file
  std::ifstream input_file;
  input_file.open(input_path.data(), std::ios::in | std::ios::binary);

  // read dummy header (44 bytes of garbage?)
  char dummy_header[MONKE_DUMMY_HEADER_LENGTH];
  input_file.read(dummy_header, sizeof(dummy_header));

  // read password index; not needed for Bloons TD 6
  uint64_t password_index;
  input_file.read(reinterpret_cast<char*>(&password_index), sizeof(password_index));

  // read salt
  char salt[MONKE_SALT_LENGTH];
  input_file.read(salt, sizeof(salt));

  // derive key and iv from salt and password
  CryptoPP::byte derived_key[MONKE_KEY_LENGTH + MONKE_IV_LENGTH];
  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf2;
  pbkdf2.DeriveKey(derived_key, MONKE_KEY_LENGTH + MONKE_IV_LENGTH, 0, (const CryptoPP::byte*)password.data(), password.size(), (const CryptoPP::byte*)salt, sizeof(salt), MONKE_DERIVE_ITERATIONS, 0.0f);

  // set key and iv
  CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
  decryptor.SetKeyWithIV(derived_key + MONKE_IV_LENGTH, MONKE_KEY_LENGTH, derived_key, MONKE_IV_LENGTH);

  // open output file
  std::ofstream output_file;
  output_file.open(output_path.data(), std::ios::out | std::ios::binary);

  // decrypt data
  std::vector<CryptoPP::byte> decrypted_data;
  CryptoPP::FileSource file_source(input_file, true, new CryptoPP::StreamTransformationFilter(decryptor, new CryptoPP::VectorSink(decrypted_data)));
  
  // decompress data and write to output file
  CryptoPP::VectorSource array_source(decrypted_data, true, new CryptoPP::ZlibDecompressor(new CryptoPP::FileSink(output_file)));

  // close file streams
  input_file.close();
  output_file.close();
}
