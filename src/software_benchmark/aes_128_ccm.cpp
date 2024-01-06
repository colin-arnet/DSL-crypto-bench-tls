// AES_128_CCM code is taken from the OpenSSL documentation

#include <iostream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using std::string;
using std::cout;
using std::endl;

int encrypt_aes_128_ccm(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
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
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)){
        cout << "ERROR: initialize encryption operation" << endl;
        return -1;
    }

    /*
     * Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example.
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL)){
        cout << "ERROR: set IV length to 7" << endl;
    }

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

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

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        cout << "ERROR: AAD, encryption" << endl;
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
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag)){
        cout << "ERROR: get tag" << endl;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes_128_ccm(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag, int tag_len,
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
        cout << "ERROR: create context" << endl;
    }

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL)){
        cout << "ERROR: initialize decryption operation" << endl;
        return -1;
    }

    /* Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL)){
        cout << "ERROR: set IV length to 7" << endl;
        return -1;
    }

    /* Set expected tag value. */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag)){
        cout << "ERROR: set expected tag value" << endl;
        return -1;
    }

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        cout << "ERROR: initialize key and IV" << endl;
        return -1;
    }

    /* Provide the total ciphertext length */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len)){
        cout << "ERROR: provide total ciphertext length" << endl;
        return -1;
    }

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        cout << "ERROR: AAD, decryption" << endl;
        return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
