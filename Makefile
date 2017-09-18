all: validateSct getTbsCertificate extractSCT validateSelfsigned

x509-extension_pac.cc:
	binpac x509-extension.pac

extractSCT: extractSCT.cc x509-extension_pac.cc
	c++ extractSCT.cc -I. -I/opt/local/include -L/opt/local/lib -o extractSCT -g -std=c++14 -Wall -lcrypto -lssl -Wno-unused-label -Wno-unused-variable -lbinpac

validateSct: validateSct.cc
	c++ validateSct.cc -I. -I/opt/local/include -L/opt/local/lib -o validateSct -g -std=c++14 -Wall -lcrypto -Wno-unused-variable -lssl

getTbsCertificate: getTbsCertificate.cc
	c++ getTbsCertificate.cc -I. -I/opt/local/include -L/opt/local/lib -o getTbsCertificate -g -std=c++14 -Wall -Wno-unused-variable -lcrypto -lssl

validateSelfsigned: validateSelfsigned.cc
	c++ validateSelfsigned.cc -I. -I/opt/local/include -L/opt/local/lib -o validateSelfsigned -g -std=c++14 -Wall -Wno-unused-variable -lcrypto -lssl

clean:
	rm -f getTbsCertificate validateSct extractSCT validateSelfsigned x509-extension_pac.cc x509-extension_pac.h
	rm -rf extractSCT.dSYM getTbsCertificate.dSYM validateSct.dSYM validateSelfsigned.dSYM
