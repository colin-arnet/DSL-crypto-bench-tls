#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <chrono>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "software_benchmark.hpp"
#include "aes_128_gcm.hpp"
#include "aes_256_gcm.hpp"
#include "aes_128_ccm.hpp"
#include "chacha20_poly1305.hpp"

using std::string;
using std::cout;
using std::endl;
using std::vector;
using namespace std::chrono;


// transform to GB/s
// 1'000'000 microseconds = 1 second
// 1'000'000'000 bytes = 1 GB
// (bytes / 1'000'000'000) / (microseconds / 1'000'000) = GB/s
// (bytes * 1'000'000) / (microseconds * 1'000'000'000) = GB/s
// (bytes / microseconds) * 1 / 1'000 = GB/s
// (bytes / microseconds) / 1'000 = GB/s

int aad_len = 64;

void openssl_setup(){
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
}
void openssl_cleanup(){
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}

void print_vector(vector<unsigned char*> vector){
    for(long unsigned int i = 0; i < vector.size(); i++){
        cout << vector[i] << " , ";
    }
    cout << endl;
}

void benchmark_aes_128_gcm(Benchmark_Config config){
    string name = "AES_128_GCM";
    cout << name << endl;
    vector<double> encrypt_time(config.runs, 0);
    vector<double> decrypt_time(config.runs, 0);
    vector<double> encrypt_throughput(config.runs, 0);
    vector<double> decrypt_throughput(config.runs, 0);
    int bytes = config.num_msg * config.msg_size;
    for(int k = 0; k < config.runs; k++){
        // initialize vectors
        openssl_setup();
        
        vector<unsigned char*> plaintext(config.num_msg, NULL);
        vector<unsigned char*> new_plaintext(config.num_msg, NULL);
        vector<unsigned char*> ciphertext(config.num_msg, NULL);
        vector<int> ciphertext_len(config.num_msg, -1);
        vector<int> plaintext_len(config.num_msg, -1);
        vector<unsigned char*> tag(config.num_msg, NULL);
        vector<unsigned char*> iv(config.num_msg, NULL);
        vector<unsigned char*> aad(config.num_msg, NULL);

        unsigned char* key = (unsigned char*) malloc(config.key_length / 8);
        RAND_bytes(key, config.key_length / 8);
        int iv_len = 12;

        // allocate memoryy
        for(int i = 0; i < config.num_msg; i++){
            // create messages
            plaintext[i] = (unsigned char*) malloc(config.msg_size);
            RAND_bytes(plaintext[i], config.msg_size);
            // create AAD
            aad[i] = (unsigned char*) malloc(aad_len);
            RAND_bytes(aad[i], aad_len);
            // allocate memory for decrypted text, ciphertext and tag
            new_plaintext[i] = (unsigned char*) malloc(config.msg_size);
            ciphertext[i] = (unsigned char*) malloc(config.msg_size);
            tag[i] = (unsigned char*) malloc(16);
            // setup unique iv; iv[0] is random and iv[i] is the incremented version of iv[i-1]
            if(i == 0){
                iv[i] = (unsigned char*) malloc(iv_len);
                RAND_bytes(iv[i], iv_len);
            } else{
                iv[i] = (unsigned char*) malloc(iv_len);
                memcpy(iv[i], iv[i-1], iv_len);
                (*iv[i])++;
            }
        }

        // encrypt and measure time
        auto start_encrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            ciphertext_len[i] = encrypt_aes_128_gcm(plaintext[i], config.msg_size, aad[i], aad_len, key, iv[i], iv_len, ciphertext[i], tag[i]);
            if (ciphertext_len[i] == -1){
                cout << "ERROR: encryption fail" << endl;
            }
        }
        auto end_encrypt = high_resolution_clock::now();

        // decrypt and measure time
        auto start_decrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            plaintext_len[i] = decrypt_aes_128_gcm(ciphertext[i], ciphertext_len[i], aad[i], aad_len, tag[i], key, iv[i], iv_len, new_plaintext[i]);
            if(plaintext_len[i] == -1){
                cout << "ERROR: decryption fail" << endl;
            }
        }
        auto end_decrypt = high_resolution_clock::now();

        encrypt_time[k] = duration_cast<microseconds>(end_encrypt - start_encrypt).count();
        decrypt_time[k] = duration_cast<microseconds>(end_decrypt - start_decrypt).count();

        encrypt_throughput[k] = (bytes / encrypt_time[k]) / 1000.0;
        decrypt_throughput[k] = (bytes / decrypt_time[k]) / 1000.0;
        
        // cleanup
        for(int i = 0; i < config.num_msg; i++){
            free(plaintext[i]);
            free(new_plaintext[i]);
            free(ciphertext[i]);
            free(iv[i]);
            free(tag[i]);
            free(aad[i]);
        }
        free(key);
        openssl_cleanup();
    }
    Benchmark_Result encrypt_result(name + "_encrypt", config.runs, encrypt_time, encrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    Benchmark_Result decrypt_result(name + "_decrypt", config.runs, decrypt_time, decrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    encrypt_result.print();
    decrypt_result.print();
    encrypt_result.store_data();
    decrypt_result.store_data();
}

void benchmark_aes_256_gcm(Benchmark_Config config){
    string name = "AES_256_GCM";
    cout << name << endl;
    vector<double> encrypt_time(config.runs, 0);
    vector<double> decrypt_time(config.runs, 0);
    vector<double> encrypt_throughput(config.runs, 0);
    vector<double> decrypt_throughput(config.runs, 0);
    int bytes = config.num_msg * config.msg_size;
    for(int k = 0; k < config.runs; k++){
        // initialize vectors
        openssl_setup();
        
        vector<unsigned char*> plaintext(config.num_msg, NULL);
        vector<unsigned char*> new_plaintext(config.num_msg, NULL);
        vector<unsigned char*> ciphertext(config.num_msg, NULL);
        vector<int> ciphertext_len(config.num_msg, -1);
        vector<int> plaintext_len(config.num_msg, -1);
        vector<unsigned char*> tag(config.num_msg, NULL);
        vector<unsigned char*> iv(config.num_msg, NULL);
        vector<unsigned char*> aad(config.num_msg, NULL);

        unsigned char* key = (unsigned char*) malloc(config.key_length / 8);
        RAND_bytes(key, config.key_length / 8);
        int iv_len = 12;

        // allocate memoryy
        for(int i = 0; i < config.num_msg; i++){
            // create messages
            plaintext[i] = (unsigned char*) malloc(config.msg_size);
            RAND_bytes(plaintext[i], config.msg_size);
            // create AAD
            aad[i] = (unsigned char*) malloc(aad_len);
            RAND_bytes(aad[i], aad_len);
            // allocate memory for decrypted text, ciphertext and tag
            new_plaintext[i] = (unsigned char*) malloc(config.msg_size);
            ciphertext[i] = (unsigned char*) malloc(config.msg_size);
            tag[i] = (unsigned char*) malloc(16);
            // setup unique iv; iv[0] is random and iv[i] is the incremented version of iv[i-1]
            if(i == 0){
                iv[i] = (unsigned char*) malloc(iv_len);
                RAND_bytes(iv[i], iv_len);
            } else{
                iv[i] = (unsigned char*) malloc(iv_len);
                memcpy(iv[i], iv[i-1], iv_len);
                (*iv[i])++;
            }
        }

        // encrypt and measure time
        auto start_encrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            ciphertext_len[i] = encrypt_aes_256_gcm(plaintext[i], config.msg_size, aad[i], aad_len, key, iv[i], iv_len, ciphertext[i], tag[i]);
            if (ciphertext_len[i] == -1){
                cout << "ERROR: encryption fail" << endl;
            }
        }
        auto end_encrypt = high_resolution_clock::now();

        // decrypt and measure time
        auto start_decrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            plaintext_len[i] = decrypt_aes_256_gcm(ciphertext[i], ciphertext_len[i], aad[i], aad_len, tag[i], key, iv[i], iv_len, new_plaintext[i]);
            if(plaintext_len[i] == -1){
                cout << "ERROR: decryption fail" << endl;
            }
        }
        auto end_decrypt = high_resolution_clock::now();

        encrypt_time[k] = duration_cast<microseconds>(end_encrypt - start_encrypt).count();
        decrypt_time[k] = duration_cast<microseconds>(end_decrypt - start_decrypt).count();

        encrypt_throughput[k] = (bytes / encrypt_time[k]) / 1000.0;
        decrypt_throughput[k] = (bytes / decrypt_time[k]) / 1000.0;

        // cleanup
        for(int i = 0; i < config.num_msg; i++){
            free(plaintext[i]);
            free(new_plaintext[i]);
            free(ciphertext[i]);
            free(iv[i]);
            free(tag[i]);
            free(aad[i]);
        }
        free(key);
        
        openssl_cleanup();
    }
    Benchmark_Result encrypt_result(name + "_encrypt", config.runs, encrypt_time, encrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    Benchmark_Result decrypt_result(name + "_decrypt", config.runs, decrypt_time, decrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    encrypt_result.print();
    decrypt_result.print();
    encrypt_result.store_data();
    decrypt_result.store_data();
}

void benchmark_aes_128_ccm_x(Benchmark_Config config, int tag_len){
    string name = "AES_128_CCM_" + std::to_string(tag_len);
    cout << name << endl;
    vector<double> encrypt_time(config.runs, 0);
    vector<double> decrypt_time(config.runs, 0);
    vector<double> encrypt_throughput(config.runs, 0);
    vector<double> decrypt_throughput(config.runs, 0);
    int bytes = config.num_msg * config.msg_size;
    for(int k = 0; k < config.runs; k++){
        // initialize
        // initialize vectors
        openssl_setup();
        
        vector<unsigned char*> plaintext(config.num_msg, NULL);
        vector<unsigned char*> new_plaintext(config.num_msg, NULL);
        vector<unsigned char*> ciphertext(config.num_msg, NULL);
        vector<int> ciphertext_len(config.num_msg, -1);
        vector<int> plaintext_len(config.num_msg, -1);
        vector<unsigned char*> tag(config.num_msg, NULL);
        vector<unsigned char*> iv(config.num_msg, NULL);
        vector<unsigned char*> aad(config.num_msg, NULL);

        unsigned char* key = (unsigned char*) malloc(config.key_length / 8);
        RAND_bytes(key, config.key_length / 8);
        int iv_len = 7;

        // allocate memoryy
        for(int i = 0; i < config.num_msg; i++){
            // create messages
            plaintext[i] = (unsigned char*) malloc(config.msg_size);
            RAND_bytes(plaintext[i], config.msg_size);
            // create AAD
            aad[i] = (unsigned char*) malloc(aad_len);
            RAND_bytes(aad[i], aad_len);
            // allocate memory for decrypted text, ciphertext and tag
            new_plaintext[i] = (unsigned char*) malloc(config.msg_size);
            ciphertext[i] = (unsigned char*) malloc(config.msg_size);
            tag[i] = (unsigned char*) malloc(tag_len);
            // setup unique iv; iv[0] is random and iv[i] is the incremented version of iv[i-1]
            if(i == 0){
                iv[i] = (unsigned char*) malloc(iv_len);
                RAND_bytes(iv[i], iv_len);
            } else{
                iv[i] = (unsigned char*) malloc(iv_len);
                memcpy(iv[i], iv[i-1], iv_len);
                (*iv[i])++;
            }
        }

        // encrypt and measure time
        auto start_encrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            ciphertext_len[i] = encrypt_aes_128_ccm(plaintext[i], config.msg_size, aad[i], aad_len, key, iv[i], ciphertext[i], tag[i], tag_len);
            if (ciphertext_len[i] == -1){
                cout << "ERROR: encryption fail" << endl;
            }
        }
        auto end_encrypt = high_resolution_clock::now();

        // decrypt and measure time
        auto start_decrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            plaintext_len[i] = decrypt_aes_128_ccm(ciphertext[i], ciphertext_len[i], aad[i], aad_len, tag[i], tag_len, key, iv[i], new_plaintext[i]);
            if(plaintext_len[i] == -1){
                cout << "ERROR: decryption fail" << endl;
            }
        }
        auto end_decrypt = high_resolution_clock::now();

        encrypt_time[k] = duration_cast<microseconds>(end_encrypt - start_encrypt).count();
        decrypt_time[k] = duration_cast<microseconds>(end_decrypt - start_decrypt).count();

        encrypt_throughput[k] = (bytes / encrypt_time[k]) / 1000.0;
        decrypt_throughput[k] = (bytes / decrypt_time[k]) / 1000.0;

        // cleanup
        for(int i = 0; i < config.num_msg; i++){
            free(plaintext[i]);
            free(new_plaintext[i]);
            free(ciphertext[i]);
            free(iv[i]);
            free(tag[i]);
            free(aad[i]);
        }
        free(key);
        
        openssl_cleanup();
    }
    Benchmark_Result encrypt_result(name + "_encrypt", config.runs, encrypt_time, encrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    Benchmark_Result decrypt_result(name + "_decrypt", config.runs, decrypt_time, decrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    encrypt_result.print();
    decrypt_result.print();
    encrypt_result.store_data();
    decrypt_result.store_data();
}

void benchmark_chacha20_poly1305(Benchmark_Config config){
    string name = "CHACHA20_POLY1305";
    cout << name << endl;
    vector<double> encrypt_time(config.runs, 0);
    vector<double> decrypt_time(config.runs, 0);
    vector<double> encrypt_throughput(config.runs, 0);
    vector<double> decrypt_throughput(config.runs, 0);
    int bytes = config.num_msg * config.msg_size;
    for(int k = 0; k < config.runs; k++){
        // initialize
        // initialize vectors
        openssl_setup();
        
        vector<unsigned char*> plaintext(config.num_msg, NULL);
        vector<unsigned char*> new_plaintext(config.num_msg, NULL);
        vector<unsigned char*> ciphertext(config.num_msg, NULL);
        vector<int> ciphertext_len(config.num_msg, -1);
        vector<int> plaintext_len(config.num_msg, -1);
        vector<unsigned char*> tag(config.num_msg, NULL);
        vector<unsigned char*> iv(config.num_msg, NULL);
        vector<unsigned char*> aad(config.num_msg, NULL);

        unsigned char* key = (unsigned char*) malloc(32);
        RAND_bytes(key, 32);
        int iv_len = 12;
        int tag_len = 16;
          

        // allocate memoryy
        for(int i = 0; i < config.num_msg; i++){
            // create messages
            plaintext[i] = (unsigned char*) malloc(config.msg_size);
            RAND_bytes(plaintext[i], config.msg_size);
            // create AAD
            aad[i] = (unsigned char*) malloc(aad_len);
            // allocate memory for decrypted text, ciphertext and tag
            new_plaintext[i] = (unsigned char*) malloc(config.msg_size);
            ciphertext[i] = (unsigned char*) malloc(config.msg_size);
            tag[i] = (unsigned char*) malloc(tag_len);
            // setup unique iv; iv[0] is random and iv[i] is the incremented version of iv[i-1]
            if(i == 0){
                iv[i] = (unsigned char*) malloc(iv_len);
                RAND_bytes(iv[i], iv_len);
            } else{
                iv[i] = (unsigned char*) malloc(iv_len);
                memcpy(iv[i], iv[i-1], iv_len);
                (*iv[i])++;
            }
        }

        // encrypt and measure time
        auto start_encrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            ciphertext_len[i] = encrypt_chacha20_poly1305(plaintext[i], config.msg_size, aad[i], aad_len, key, iv[i], ciphertext[i], tag[i]);
            if (ciphertext_len[i] == -1){
                cout << "ERROR: encryption fail" << endl;
            }
        }
        auto end_encrypt = high_resolution_clock::now();

        // decrypt and measure time
        auto start_decrypt = high_resolution_clock::now();
        for(int i = 0; i < config.num_msg; i++){
            plaintext_len[i] = decrypt_chacha20_poly1305(ciphertext[i], ciphertext_len[i], aad[i], aad_len, tag[i], key, iv[i], new_plaintext[i]);
            if(plaintext_len[i] == -1){
                cout << "ERROR: decryption fail" << endl;
            }
        }
        auto end_decrypt = high_resolution_clock::now();
    
        encrypt_time[k] = duration_cast<microseconds>(end_encrypt - start_encrypt).count();
        decrypt_time[k] = duration_cast<microseconds>(end_decrypt - start_decrypt).count();

        encrypt_throughput[k] = (bytes / encrypt_time[k]) / 1000.0;
        decrypt_throughput[k] = (bytes / decrypt_time[k]) / 1000.0;

        // cleanup
        for(int i = 0; i < config.num_msg; i++){
            free(plaintext[i]);
            free(new_plaintext[i]);
            free(ciphertext[i]);
            free(iv[i]);
            free(tag[i]);
        }
        free(key);
        
        openssl_cleanup();
    }
    Benchmark_Result encrypt_result(name + "_encrypt", config.runs, encrypt_time, encrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    Benchmark_Result decrypt_result(name + "_decrypt", config.runs, decrypt_time, decrypt_throughput, config.num_msg, config.msg_size, config.data_path);
    encrypt_result.print();
    decrypt_result.print();
    encrypt_result.store_data();
    decrypt_result.store_data();
}
 
void benchmark_rsa_asymmetric(Benchmark_Config config){
    string name = "ASYMMETRIC RSA-" + std::to_string(config.rsa_key_length);
    cout << name  << endl;
    vector<double> encrypt_time(config.runs, 0);
    vector<double> decrypt_time(config.runs, 0);
    vector<double> encrypt_throughput(config.runs, 0);
    vector<double> decrypt_throughput(config.runs, 0);
    // compute message size for specific key
    int msg_size = (config.rsa_key_length / 8 - 2) - 2 * (256 / 8);
    int num_msg;
    for(int k = 0; k < config.runs; k++){
        cout << "RUN NR. " << std::to_string(k) << endl;
        vector<unsigned char*> plaintext;
        vector<int> plaintext_len;
        // number of bytes to be encrypted
        int bytes = config.msg_size * config.num_msg;
        // form messages with correct length
        unsigned char* msg;
        num_msg = 0;
        while(bytes - msg_size > 0){
            msg = (unsigned char*) malloc(msg_size);
            RAND_bytes(msg, msg_size);
            plaintext.push_back(msg);
            plaintext_len.push_back(msg_size);
            bytes -= msg_size;
            num_msg++;
        }
        if(bytes > 0){
            msg = (unsigned char*) malloc(bytes);
            RAND_bytes(msg, bytes);
            plaintext.push_back(msg);
            plaintext_len.push_back(bytes);
            num_msg++;
        }
        

        // intitialize ciphertext memory
        vector<unsigned char*> ciphertext(num_msg, NULL);
        vector<int> ciphertext_len(num_msg, -1);
        vector<unsigned char*> new_plaintext(num_msg, NULL);
        for(int i = 0; i < num_msg; i++){
            ciphertext[i] = (unsigned char*) malloc(config.rsa_key_length);
            new_plaintext[i] = (unsigned char*) malloc(config.rsa_key_length);        
        }
        
        // generate RSA key pair
        RSA* key_pair = RSA_generate_key(config.rsa_key_length, 65537, NULL, NULL);
        // encrypt messages and measure time
        auto start_encrypt = high_resolution_clock::now();
        for(int i = 0; i < num_msg; i++){
            ciphertext_len[i] = RSA_public_encrypt(plaintext_len[i], plaintext[i], ciphertext[i], key_pair, RSA_PKCS1_OAEP_PADDING);
            if(ciphertext_len[i] == -1){
                cout << "ERROR: RSA encryption error" << endl;
            }
        }
        auto end_encrypt = high_resolution_clock::now();

        // decrypt messages and measure time
        auto start_decrypt = high_resolution_clock::now();
        for(int i = 0; i < num_msg; i++){
            plaintext_len[i] = RSA_private_decrypt(ciphertext_len[i], ciphertext[i], new_plaintext[i], key_pair, RSA_PKCS1_OAEP_PADDING);
            if(plaintext_len[i] == -1){
                cout << "ERROR: RSA decryption error" << endl;
            }
        }
        auto end_decrypt = high_resolution_clock::now();

        bytes = config.num_msg * config.msg_size;

        encrypt_time[k] = duration_cast<microseconds>(end_encrypt - start_encrypt).count();
        decrypt_time[k] = duration_cast<microseconds>(end_decrypt - start_decrypt).count();

        encrypt_throughput[k] = (bytes / encrypt_time[k]) / 1000.0;
        decrypt_throughput[k] = (bytes / decrypt_time[k]) / 1000.0;
        
        for(int i = 0; i < num_msg; i++){
            free(plaintext[i]);
            free(new_plaintext[i]);
            free(ciphertext[i]);
        }
    }
    Benchmark_Result encrypt_result(name + "_encrypt", config.runs, encrypt_time, encrypt_throughput, num_msg, msg_size, config.data_path);
    Benchmark_Result decrypt_result(name + "_decrypt", config.runs, decrypt_time, decrypt_throughput, num_msg, msg_size, config.data_path);
    encrypt_result.print();
    decrypt_result.print(); 
    encrypt_result.store_data();
    decrypt_result.store_data();
}


void software_benchmark(Benchmark_Config config){
    benchmark_aes_128_gcm(config);
    benchmark_aes_256_gcm(config);
    benchmark_aes_128_ccm_x(config, 16);
    benchmark_aes_128_ccm_x(config, 12);
    benchmark_aes_128_ccm_x(config, 8);
    benchmark_chacha20_poly1305(config);
    // benchmark_rsa_asymmetric(config);
}