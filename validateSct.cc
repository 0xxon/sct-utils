// See the file "COPYING" in the main distribution directory for copyright.

#include <cppcodec/base64_default_rfc4648.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <arpa/inet.h>

#if !defined(__DARWIN__) && !defined(__APPLE__)
inline uint64_t ntohll(uint64_t i)
	{
	u_char c;
	union {
		uint64_t i;
		u_char c[8];
	} x;

	x.i = i;
	c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
	c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
	c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
	c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
	return x.i;
	}

inline uint64_t htonll(uint64_t i) { return ntohll(i); }
#endif

std::string toHex(const std::string& s, bool upper_case = false) {
	std::ostringstream ret;

	for (std::string::size_type i = 0; i < s.length(); ++i) {
		uint8_t p = s[i];
  	ret << std::hex << std::setfill('0') << std::setw(1) << (upper_case ? std::uppercase : std::nouppercase) << (int)p;
	}

	return ret.str();
}

template <typename T>
std::string sha256(T from) {
	unsigned char* out = SHA256(reinterpret_cast<const unsigned char*>(&from[0]), from.size(), nullptr);
	std::string outstr(reinterpret_cast<const char*>(out), 32);
	return outstr;
}

template <typename T>
std::string sha1(T from) {
	unsigned char* out = SHA1(reinterpret_cast<const unsigned char*>(&from[0]), from.size(), nullptr);
	std::string outstr(reinterpret_cast<const char*>(out), 20);
	return outstr;
}

int main(int argc, char** argv) {
	std::ifstream in("certificates_scttest");
	std::string line;

	if ( !in ) {
		std::cerr << "Could not open source certificate file \"certificates_scttest\"" << std::endl;
		return -1;
	}

	if ( argc != 4 ) {
		std::cerr << "Argument error. Required arguments:" << std::endl;
		std::cerr << "validateSct [log key] [timestamp] [signature]" << std::endl;
		std::cerr << "log key and signature expected in base64" << std::endl;
		return -1;
	}

	//std::string logid_base64 = argv[1];
	std::string log_key_base64 = argv[1];
	uint64_t timestamp = strtoull(argv[2], nullptr, 10);
	uint64_t timestamp_network = htonll(timestamp);
	std::string signature_base64 = argv[3];
	//std::vector<uint8_t> logid = base64::decode(logid_base64);
	std::vector<uint8_t> log_key = base64::decode(log_key_base64);
	std::vector<uint8_t> signature = base64::decode(signature_base64);

	//std::cerr << "Logid: " << logid_base64 << std::endl;
	std::cerr << "Log key: " << log_key_base64 << std::endl;
	std::cerr << "Timestamp: " << timestamp << std::endl;
	std::cerr << "Signature: " << signature_base64 << std::endl;

	std::string common_data;
	common_data.push_back(0); // version
	common_data.push_back(0); // signature_type -> certificate_timestamp
	common_data.append(reinterpret_cast<const char*>(&timestamp_network), sizeof(timestamp_network)); // timestamp -> 64 bits
	assert(sizeof(timestamp_network) == 8);
	common_data.append("\0\0", 2); // entry-type: x509_entry

	const unsigned char *key_char = reinterpret_cast<const unsigned char*>(&log_key[0]);
	EVP_PKEY* key = d2i_PUBKEY(nullptr, &key_char, log_key.size());
	assert(key);
	const EVP_MD* hash = EVP_sha256();

	int currline = 1;
	while ( std::getline(in, line) ) {
		std::vector<uint8_t> decoded = base64::decode(line);
		std::string testdata = common_data;
		uint32_t cert_length_network = htonl(decoded.size());
		assert( sizeof(cert_length_network) == 4);
		testdata.append(reinterpret_cast<const char*>(&cert_length_network)+1, 3); // 3 bytes certificate length
		testdata.append(reinterpret_cast<const char*>(&decoded[0]), decoded.size());
		testdata.append("\0\0", 2); // no extensions

		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
		if ( ! EVP_DigestVerifyInit(mdctx, NULL, hash, NULL, key) ) {
			std::cerr <<  "Could not init signature verification " << currline << std::endl;
			return -1;
		}

		if ( ! EVP_DigestVerifyUpdate(mdctx, testdata.data(), testdata.size()) ) {
			std::cerr <<  "Could not update digest for verification " << currline << std::endl;
			return -1;
		}

		int success = EVP_DigestVerifyFinal(mdctx, reinterpret_cast<const unsigned char*>(&signature[0]), signature.size());
		if ( success ) {
			std::string cert_str;
			cert_str.append(reinterpret_cast<const char*>(&decoded[0]), decoded.size()); // der-encoded tbscertificate
			std::cout << "Valid SCT test\t" << currline << "\t" << toHex(sha1(cert_str)) << "\t" << toHex(sha256(cert_str)) << std::endl;
			return 0;
		}

		EVP_MD_CTX_destroy(mdctx);
		currline++;
	}

	std::cerr << "Done" << std::endl;
	in.close();
	return 1;
}

