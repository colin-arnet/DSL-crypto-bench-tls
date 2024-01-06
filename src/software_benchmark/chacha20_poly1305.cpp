// CHACHA20_POLY1305 code is based on the AES_GCM code from the OpenSSL documentation.

#include <iostream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using std::string;
using std::cout;
using std::endl;

int encrypt_chacha20_poly1305(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cout << "ERROR: create context" << endl;
        return -1;
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)){
        cout << "ERROR: initialize encryption operation" << endl;
        return -1;
    }

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        cout << "ERROR: initialize key and IV" << endl;
        return -1;
    }

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len)){
        cout << "ERROR: provide total plaintext length" << endl;
        return -1;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        cout << "ERROR: encryption" << endl;
        return -1;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        cout << "ERROR: finalize encrytpion" << endl;
        return -1;
    }
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        cout << "ERROR: get tag" << endl;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_chacha20_poly1305(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cout << "ERROR: new context" << endl;
        return -1;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)){
        cout << "ERROR: initialize decryption operation" << endl;
        return -1;
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        cout << "ERROR: initialize key and IV" << endl;
        return -1;
    }
    
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        cout << "ERROR: decrypt message" << endl;
        return -1;
    }
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        cout << "ERROR: set tag value" << endl;
        return -1;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        cout << "ERROR: verify failed" << endl;
        return -1;
    }
}
