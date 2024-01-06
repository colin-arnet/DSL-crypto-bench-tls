
int encrypt_aes_128_ccm(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag, int tag_len);

int decrypt_aes_128_ccm(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag, int tag_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext);