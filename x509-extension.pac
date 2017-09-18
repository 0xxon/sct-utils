# See the file "COPYING" in the main distribution directory for copyright.
#
# Binpac analyzer for X.509 extensions
# we just use it for the SignedCertificateTimestamp at the moment


analyzer X509Extension withcontext {
	connection: MockConnection;
	flow:       SignedCertTimestampExt;
};

connection MockConnection() {
	upflow = SignedCertTimestampExt;
	downflow = SignedCertTimestampExt;
};

%include x509-signed_certificate_timestamp.pac

# The base record
type HandshakeRecord() = record {
  signed_certificate_timestamp_list: SignedCertificateTimestampList(this)[] &transient;
} &byteorder = bigendian;

flow SignedCertTimestampExt {
	flowunit = HandshakeRecord withcontext(connection, this);
};

refine connection MockConnection += {

	function proc_signedcertificatetimestamp(version: uint8, logid: const_bytestring, timestamp: uint64, digitally_signed_algorithms: SignatureAndHashAlgorithm, digitally_signed_signature: const_bytestring) : bool
		%{
		std::string logid_str(reinterpret_cast<const char*>(logid.begin()), logid.length());
		std::string signature_str(reinterpret_cast<const char*>(digitally_signed_signature.begin()), digitally_signed_signature.length());
		::callback(
			version,
			logid_str,
			timestamp,
			digitally_signed_algorithms->HashAlgorithm(),
			digitally_signed_algorithms->SignatureAlgorithm(),
			signature_str
		);

		return true;
		%}
};

refine typeattr SignedCertificateTimestamp += &let {
	proc : bool = $context.connection.proc_signedcertificatetimestamp(version, logid, timestamp, digitally_signed_algorithms, digitally_signed_signature);
};
