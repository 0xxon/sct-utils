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

void removeSCT(X509* x) {
#ifdef NID_ct_precert_scts
		int pos = X509_get_ext_by_NID(x, NID_ct_precert_scts, -1);
#else
		int num_ext = X509_get_ext_count(x);
		int pos = -1;
		for ( int k = 0; k < num_ext; ++k ) {
			char oid[256];
			X509_EXTENSION* ex = X509_get_ext(x, k);
			ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
			OBJ_obj2txt(oid, 255, ext_asn, 1);
			if ( strcmp(oid, "1.3.6.1.4.1.11129.2.4.2") == 0 ) {
				pos = k;
				break;
				}
			}
#endif
		if ( pos < 0 ) {
			std::cerr << "NID_ct_precert_scts not found" << std::endl;
			exit(-1);
		}
		X509_EXTENSION_free(X509_delete_ext(x, pos));
#ifdef NID_ct_precert_scts
		assert( X509_get_ext_by_NID(x, NID_ct_precert_scts, -1) == -1 );
#endif
}

void removePoison(X509* x) {
#ifdef NID_ct_precert_scts
		int pos = X509_get_ext_by_NID(x, NID_ct_precert_poison, -1);
#else
		int num_ext = X509_get_ext_count(x);
		int pos = -1;
		for ( int k = 0; k < num_ext; ++k ) {
			char oid[256];
			X509_EXTENSION* ex = X509_get_ext(x, k);
			ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
			OBJ_obj2txt(oid, 255, ext_asn, 1);
			if ( strcmp(oid, "1.3.6.1.4.1.11129.2.4.3") == 0 ) {
				pos = k;
				break;
				}
			}
#endif
		if ( pos < 0 ) {
			std::cerr << "NID_ct_precert_poison not found" << std::endl;
			exit(-1);
		}
		X509_EXTENSION_free(X509_delete_ext(x, pos));
#ifdef NID_ct_precert_scts
		assert( X509_get_ext_by_NID(x, NID_ct_precert_scts, -1) == -1 );
#endif
}

void usage() {
	std::cerr << "Usage:" << std::endl;
	std::cerr << "getTbsCertificate poison: remove poison from certificate" << std::endl;
	std::cerr << "getTbsCertificate extension: remove SCT extension from certificate" << std::endl << std::endl;
	exit(-1);
}

int main(int argc, char** argv) {
	if ( argc != 2 ) {
		usage();
	}
	std::string arg = argv[1];
	bool extractPoison = false;
	if ( arg == "poison" )
		extractPoison = true;
	else if ( arg == "extension" ) {
		// noop
	} else
		usage();
	std::ifstream in("certificates");
	std::string line;

	if ( !in ) {
		std::cerr << "Could not open source certificate file \"certificates\"" << std::endl;
		return -1;
	}

	while ( std::getline(in, line) ) {
		std::vector<uint8_t> decoded = base64::decode(line);
		const unsigned char* cert_char = reinterpret_cast<const unsigned char*>(&decoded[0]);
		X509* cert = d2i_X509(nullptr, &cert_char, decoded.size());
		if ( ! cert ) {
			std::cerr << "OpenSSl could not parse cert" << std::endl;
			return -1;
		}
		if ( extractPoison )
			removePoison(cert);
		else
			removeSCT(cert);
		cert->cert_info->enc.modified = 1;
		unsigned char *cert_out = nullptr;
		int cert_length = i2d_X509_CINF(cert->cert_info, &cert_out);
		std::string cert_str;
		cert_str.append(reinterpret_cast<const char*>(cert_out), cert_length); // der-encoded tbscertificate
		OPENSSL_free(cert_out);
		X509_free(cert);
		std::cout << base64::encode(cert_str) << "\t" << toHex(sha256(decoded)) << std::endl;
	}

	std::cerr << "Done" << std::endl;
	in.close();
	return 0;
}

