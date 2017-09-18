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

#include "x509-extension_pac.h"

std::string certhash;
std::string certhash256;

void callback(uint16_t version, std::string logid, uint64_t timestamp, uint16_t hashalg, uint16_t sigalg, std::string signature) {
	std::cout << certhash << "\t" << certhash256 << "\t" << version << "\t" << base64::encode(logid) << "\t" << timestamp << "\t" << hashalg << "\t" << sigalg << "\t" << base64::encode(signature) << std::endl;
}

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

template <typename T>
std::string sha1(T from) {
	unsigned char* out = SHA1(reinterpret_cast<const unsigned char*>(&from[0]), from.size(), nullptr);
	std::string outstr(reinterpret_cast<const char*>(out), 20);
	return outstr;
}

int main(int argc, char** argv) {
	std::ifstream in("certificates");
	std::string line;

	if ( !in ) {
		std::cerr << "Could not open source certificate file \"certificates\"" << std::endl;
		return -1;
	}

	while ( std::getline(in, line) ) {
		std::vector<uint8_t> decoded = base64::decode(line);
		const unsigned char* cert_char = reinterpret_cast<const unsigned char*>(&decoded[0]);
		std::string cert_str;
		cert_str.append(reinterpret_cast<const char*>(&decoded[0]), decoded.size());
		certhash = toHex(sha1(cert_str));
		certhash256 = toHex(sha256(cert_str));
		X509* cert = d2i_X509(nullptr, &cert_char, decoded.size());
		if ( ! cert ) {
			std::cerr << "OpenSSl could not parse cert " << certhash << std::endl;
			return -1;
		}
		int num_ext = X509_get_ext_count(cert);
		for ( int k = 0; k < num_ext; ++k ) {
			X509_EXTENSION* ex = X509_get_ext(cert, k);
			ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
			if ( OBJ_obj2nid(ext_asn) == NID_ct_precert_scts ) {
				ASN1_OCTET_STRING* ext_val = X509_EXTENSION_get_data(ex);
				// the octet string of the extension contains the octet string which in turn
				// contains the SCT. Obviously.

				unsigned char* ext_val_copy = (unsigned char*) OPENSSL_malloc(ext_val->length);
				unsigned char* ext_val_second_pointer = ext_val_copy;
				memcpy(ext_val_copy, ext_val->data, ext_val->length);
				ASN1_OCTET_STRING* inner = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char**) &ext_val_copy, ext_val->length);
				if ( !inner ) {
					std::cerr << "Could not parse extension for cert " << certhash << std::endl;
					continue;
				}

				binpac::X509Extension::MockConnection* conn = new binpac::X509Extension::MockConnection();
				binpac::X509Extension::SignedCertTimestampExt* interp = new binpac::X509Extension::SignedCertTimestampExt(conn);
				try {
					interp->NewData(inner->data, inner->data + inner->length);
				}
				catch( const binpac::Exception& e ) {
					assert(false);
				}
				OPENSSL_free(ext_val_second_pointer);
				interp->FlowEOF();
				delete interp;
				delete conn;
			}
		}
		X509_free(cert);
	}

	std::cerr << "Done" << std::endl;
	in.close();
	return 0;
}

#include "x509-extension_pac.cc"
