#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "ed25519/ed25519.h"

#define ED25519_SEED_BYTES 32U
#define sign_ed25519_BYTES_DETACHED 64U
#define sign_ed25519_PUBLICKEYBYTES 32U
#define sign_ed25519_PRIVATEKEYBYTES 64U


void xor_encrypt_decrypt(unsigned char* message, size_t message_len, unsigned char* key, size_t key_len)
{
    for (size_t i = 0; i < message_len; ++i)
    {
        message[i] ^= key[i % key_len]; // Ensure key wraps around if shorter than message
    }
}

int main()
{
    printf("Secure C2 Communcations Encrypt & Sign Algorithm - @Pyramidyon\r\n\r\n");
    char message[] = "execute_capstone";
    unsigned char xor_key[] = "xor_key_pyramidyon";

    unsigned char seed[ED25519_SEED_BYTES];
    unsigned char pubkey[sign_ed25519_PUBLICKEYBYTES];
    unsigned char seckey[sign_ed25519_PRIVATEKEYBYTES];
    unsigned char signature[sign_ed25519_BYTES_DETACHED];
    size_t message_len = strlen(message);
    size_t key_len = strlen((char*)xor_key);

    if (0 == ed25519_create_seed(seed))
    {
        printf("[i] Generated ed25519 seed\r\n");
        ed25519_create_keypair(pubkey, seckey, seed);

        // Encrypt the message
        printf("[i] Message before crypto algo %s\r\n", message);
        xor_encrypt_decrypt((unsigned char*)message, message_len, xor_key, key_len);
        printf("[i] Message After crypto algo %02X\r\n", message);

        // Sign the encrypted message
        ed25519_sign(signature, (const unsigned char*)message, message_len, pubkey, seckey);
        printf("[i] Message Signed %02X\r\n", message);

        // Verify 2 fail before decrypting to check it actually works!
        unsigned char fake_signature[sign_ed25519_BYTES_DETACHED] = { 0 };
        sprintf(fake_signature, "%s%x", signature, 0xEB);
        printf("[i] fake signature generated %02X\r\n", fake_signature);
        if (!ed25519_verify(fake_signature, (const unsigned char*)message, message_len, pubkey))
            printf("[+] Fake signature! - It works!\n");

        // Verify the signature before decrypting
        if (ed25519_verify(signature, (const unsigned char*)message, message_len, pubkey))
        {
            printf("[+] Signature is valid. Decrypting the message.\n");
            xor_encrypt_decrypt((unsigned char*)message, message_len, xor_key, key_len); // Decrypt the message
            printf("[i] Decrypted message: %s\n", message);
        }
        else
        {
            printf("[-] Signature is NOT valid. Do not decrypt.\n");
        }
    }
    else
    {
        printf("[-] Failed to generate ed25519 seed\r\n");
    }

    return 0;
}
