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
#include <openssl/ssl.h>

std::string toHex(const std::string& s, bool upper_case = false) {
	std::ostringstream ret;

	for (std::string::size_type i = 0; i < s.length(); ++i) {
		uint8_t p = s[i];
  	ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int)p;
	}

	return ret.str();
}

template <typename T>
std::string sha256(T from) {
	unsigned char* out = SHA256(reinterpret_cast<const unsigned char*>(&from[0]), from.size(), nullptr);
	std::string outstr(reinterpret_cast<const char*>(out), 32);
	return outstr;
}

int main(int argc, char** argv) {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	std::ifstream in("certificates2");
	std::string line;

	if ( !in ) {
		std::cerr << "Could not open source certificate file \"certificates2\"" << std::endl;
		return -1;
	}

	while ( std::getline(in, line) ) {
		std::vector<uint8_t> decoded = base64::decode(line);
		const unsigned char* cert_char = reinterpret_cast<const unsigned char*>(&decoded[0]);
		X509* cert = nullptr;
		d2i_X509(&cert, &cert_char, decoded.size());
		if ( ! cert ) {
			std::cerr << "OpenSSl could not parse cert" << std::endl;
			return -1;
		}
		EVP_PKEY *pkey = X509_get_pubkey(cert);
		assert(pkey);
		std::cout << X509_verify(cert, pkey) << std::endl;
		EVP_PKEY_free(pkey);
		X509_free(cert);
		//std::cout << base64::encode(cert_str) << "\t" << toHex(sha256(decoded)) << std::endl;
	}

	std::cerr << "Done" << std::endl;
	in.close();
	return 0;
}

