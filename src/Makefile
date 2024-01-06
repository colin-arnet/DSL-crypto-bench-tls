CPP = g++
CPPFLAGS = -Wall -g
SSLFLAGS = -I/home/carnet/openssl/install/include/ -L/home/carnet/openssl/install/lib64 -lcrypto -lssl
SSLLIBS = /home/carnet/openssl/install/lib64/libcrypto.a /home/carnet/openssl/install/lib64/libssl.a

main: main.o software_benchmark.o aes_128_gcm.o aes_256_gcm.o aes_128_ccm.o chacha20_poly1305.o
	$(CPP) $(CPPFLAGS) -o main main.o software_benchmark.o aes_128_gcm.o aes_256_gcm.o aes_128_ccm.o chacha20_poly1305.o $(SSLFLAGS)

main.o: main.cpp software_benchmark/software_benchmark.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c main.cpp

software_benchmark.o: software_benchmark/software_benchmark.cpp software_benchmark/software_benchmark.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c software_benchmark/software_benchmark.cpp

aes_128_gcm.o: software_benchmark/aes_128_gcm.cpp software_benchmark/aes_128_gcm.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c software_benchmark/aes_128_gcm.cpp

aes_256_gcm.o: software_benchmark/aes_256_gcm.cpp software_benchmark/aes_256_gcm.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c software_benchmark/aes_256_gcm.cpp

aes_128_ccm.o: software_benchmark/aes_128_ccm.cpp software_benchmark/aes_128_ccm.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c software_benchmark/aes_128_ccm.cpp

chacha20_poly1305.o: software_benchmark/chacha20_poly1305.cpp software_benchmark/chacha20_poly1305.hpp
	$(CPP) $(CPPFLAGS) $(SSLFLAGS) -c software_benchmark/chacha20_poly1305.cpp


clean:
	rm *.o
	rm main
