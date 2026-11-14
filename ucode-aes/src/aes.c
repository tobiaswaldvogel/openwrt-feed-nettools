#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>

#include "ucode/module.h"
#include "ucode/vm.h"


#define AES_BLOCK_SIZE       16
#define GCM_DEFAULT_IV_SIZE  12
#define GCM_DEFAULT_TAG_SIZE 16


static uc_value_t *
crypto_error(uc_vm_t *vm, const char *msg)
{
    uc_vm_raise_exception(vm, EXCEPTION_USER, "%s", msg);
    return NULL;
}


static int
get_string(
    uc_value_t *value,
    const unsigned char **data,
    size_t *length
)
{
    if (!value || ucv_type(value) != UC_STRING)
        return -1;

    *data = (const unsigned char *)ucv_string_get(value);
    *length = ucv_string_length(value);

    return 0;
}


/*
 * PKCS#7 padding.
 */
static unsigned char *
pkcs7_pad(
    const unsigned char *input,
    size_t input_len,
    size_t *output_len
)
{
    size_t pad = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
    unsigned char *output;

    *output_len = input_len + pad;

    output = malloc(*output_len);

    if (!output)
        return NULL;

    if (input_len)
        memcpy(output, input, input_len);

    memset(output + input_len, (int)pad, pad);

    return output;
}


/*
 * Validate and remove PKCS#7 padding.
 */
static int
pkcs7_unpad(
    unsigned char *buffer,
    size_t *length
)
{
    size_t len;
    size_t i;
    unsigned char pad;

    if (!buffer || !length)
        return -1;

    len = *length;

    if (len == 0 || (len % AES_BLOCK_SIZE) != 0)
        return -1;

    pad = buffer[len - 1];

    if (pad == 0 || pad > AES_BLOCK_SIZE || pad > len)
        return -1;

    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        unsigned char value = buffer[len - 1 - i];

        if (i < pad && value != pad)
            return -1;
    }

    *length = len - pad;

    return 0;
}


/*
 * AES-CBC using Mbed TLS.
 */
static uc_value_t *
aes_cbc_crypt(
    uc_vm_t *vm,
    size_t nargs,
    int key_bits,
    int decrypt
)
{
    uc_value_t *data_v = uc_fn_arg(0);
    uc_value_t *key_v  = uc_fn_arg(1);
    uc_value_t *iv_v   = uc_fn_arg(2);
    uc_value_t *pad_v  = uc_fn_arg(3);

    const unsigned char *data;
    const unsigned char *key;
    const unsigned char *iv;

    size_t data_len;
    size_t key_len;
    size_t iv_len;

    int padding = 0;

    unsigned char *input = NULL;
    unsigned char *output = NULL;

    size_t input_len;
    size_t output_len;

    mbedtls_aes_context aes;
    unsigned char iv_copy[AES_BLOCK_SIZE];

    uc_value_t *result = NULL;
    int ret;

    mbedtls_aes_init(&aes);

    if (get_string(data_v, &data, &data_len) ||
        get_string(key_v, &key, &key_len) ||
        get_string(iv_v, &iv, &iv_len)) {
        mbedtls_aes_free(&aes);

        return crypto_error(
            vm,
            "AES-CBC: arguments must be strings"
        );
    }

    if (key_bits == 128) {
        if (key_len != 16) {
            mbedtls_aes_free(&aes);

            return crypto_error(
                vm,
                "AES-128-CBC: key must be 16 bytes"
            );
        }
    }
    else {
        if (key_len != 32) {
            mbedtls_aes_free(&aes);

            return crypto_error(
                vm,
                "AES-256-CBC: key must be 32 bytes"
            );
        }
    }

    if (iv_len != AES_BLOCK_SIZE) {
        mbedtls_aes_free(&aes);

        return crypto_error(
            vm,
            "AES-CBC: IV must be 16 bytes"
        );
    }

    if (pad_v) {
        if (ucv_type(pad_v) != UC_BOOLEAN) {
            mbedtls_aes_free(&aes);

            return crypto_error(
                vm,
                "AES-CBC: padding must be boolean"
            );
        }

        padding = ucv_is_truish(pad_v);
    }

    /*
     * Prepare input.
     */
    if (!decrypt && padding) {
        input = pkcs7_pad(
            data,
            data_len,
            &input_len
        );

        if (!input) {
            mbedtls_aes_free(&aes);

            return crypto_error(
                vm,
                "AES-CBC: out of memory"
            );
        }
    }
    else {
        if ((data_len % AES_BLOCK_SIZE) != 0) {
            mbedtls_aes_free(&aes);

            /* Malformed ciphertext is a data error, not API misuse. */
            if (decrypt)
                return NULL;

            return crypto_error(
                vm,
                "AES-CBC: input is not block aligned"
            );
        }

        input_len = data_len;

        input = malloc(input_len ? input_len : 1);

        if (!input) {
            mbedtls_aes_free(&aes);

            return crypto_error(
                vm,
                "AES-CBC: out of memory"
            );
        }

        if (input_len)
            memcpy(input, data, input_len);
    }

    output_len = input_len;

    output = malloc(output_len ? output_len : 1);

    if (!output) {
        mbedtls_platform_zeroize(input, input_len);
        free(input);
        mbedtls_aes_free(&aes);

        return crypto_error(
            vm,
            "AES-CBC: out of memory"
        );
    }

    memcpy(iv_copy, iv, sizeof(iv_copy));

    if (!decrypt)
        ret = mbedtls_aes_setkey_enc(
            &aes,
            key,
            (unsigned int)key_bits
        );
    else
        ret = mbedtls_aes_setkey_dec(
            &aes,
            key,
            (unsigned int)key_bits
        );

    if (ret != 0)
        goto error;

    ret = mbedtls_aes_crypt_cbc(
        &aes,
        decrypt ? MBEDTLS_AES_DECRYPT : MBEDTLS_AES_ENCRYPT,
        input_len,
        iv_copy,
        input,
        output
    );

    if (ret != 0)
        goto error;

    mbedtls_aes_free(&aes);

    mbedtls_platform_zeroize(input, input_len);
    free(input);
    input = NULL;

    /*
     * PKCS#7 removal happens after successful CBC decryption.
     */
    if (decrypt && padding) {
        if (pkcs7_unpad(output, &output_len) != 0)
            goto error_after_ctx;
    }

    result = ucv_string_new_length(
        (const char *)output,
        output_len
    );

    mbedtls_platform_zeroize(output, output_len);
    free(output);

    return result;

error:
    mbedtls_aes_free(&aes);

    if (input) {
        mbedtls_platform_zeroize(input, input_len);
        free(input);
    }

error_after_ctx:
    if (output) {
        mbedtls_platform_zeroize(output, input_len);
        free(output);
    }

    mbedtls_platform_zeroize(iv_copy, sizeof(iv_copy));

    /* Decryption failures (e.g. bad padding) yield null. */
    if (decrypt)
        return NULL;

    return crypto_error(
        vm,
        "AES-CBC: Mbed TLS operation failed"
    );
}


/*
 * AES-GCM encryption.
 */
static uc_value_t *
aes_gcm_encrypt(
    uc_vm_t *vm,
    size_t nargs,
    int key_bits
)
{
    uc_value_t *data_v = uc_fn_arg(0);
    uc_value_t *key_v  = uc_fn_arg(1);
    uc_value_t *iv_v   = uc_fn_arg(2);
    uc_value_t *aad_v  = uc_fn_arg(3);
    uc_value_t *tag_v  = uc_fn_arg(4);

    const unsigned char *data;
    const unsigned char *key;
    const unsigned char *iv;
    const unsigned char *aad = NULL;

    size_t data_len;
    size_t key_len;
    size_t iv_len;
    size_t aad_len = 0;

    int tag_len = GCM_DEFAULT_TAG_SIZE;

    mbedtls_gcm_context ctx;
    unsigned char *ciphertext = NULL;
    unsigned char tag[GCM_DEFAULT_TAG_SIZE];

    uc_value_t *result = NULL;
    int ret;

    mbedtls_gcm_init(&ctx);

    if (get_string(data_v, &data, &data_len) ||
        get_string(key_v, &key, &key_len) ||
        get_string(iv_v, &iv, &iv_len)) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: invalid arguments"
        );
    }

    if (key_bits == 128) {
        if (key_len != 16) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-128-GCM: key must be 16 bytes"
            );
        }
    }
    else {
        if (key_len != 32) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-256-GCM: key must be 32 bytes"
            );
        }
    }

    if (iv_len == 0) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: IV must not be empty"
        );
    }

    if (aad_v) {
        if (ucv_type(aad_v) != UC_STRING) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-GCM: AAD must be a string"
            );
        }

        aad = (const unsigned char *)ucv_string_get(aad_v);
        aad_len = ucv_string_length(aad_v);
    }

    if (tag_v) {
        if (ucv_type(tag_v) != UC_INTEGER) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-GCM: tag size must be an integer"
            );
        }

        int64_t requested = ucv_int64_get(tag_v);

        if (requested < 12 || requested > 16) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-GCM: tag size must be between 12 and 16 bytes"
            );
        }

        tag_len = (int)requested;
    }

    ciphertext = malloc(data_len ? data_len : 1);

    if (!ciphertext) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: out of memory"
        );
    }

    ret = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        key,
        (unsigned int)key_bits
    );

    if (ret != 0)
        goto error;

    ret = mbedtls_gcm_crypt_and_tag(
        &ctx,
        MBEDTLS_GCM_ENCRYPT,
        data_len,
        iv,
        iv_len,
        aad,
        aad_len,
        data,
        ciphertext,
        (size_t)tag_len,
        tag
    );

    if (ret != 0)
        goto error;

    mbedtls_gcm_free(&ctx);

    result = ucv_object_new(vm);

    if (!result)
        goto error_after_ctx;

    ucv_object_add(
        result,
        "ciphertext",
        ucv_string_new_length(
            (const char *)ciphertext,
            data_len
        )
    );

    ucv_object_add(
        result,
        "tag",
        ucv_string_new_length(
            (const char *)tag,
            (size_t)tag_len
        )
    );

    mbedtls_platform_zeroize(ciphertext, data_len);
    mbedtls_platform_zeroize(tag, sizeof(tag));

    free(ciphertext);

    return result;

error:
    mbedtls_gcm_free(&ctx);

error_after_ctx:
    if (ciphertext) {
        mbedtls_platform_zeroize(ciphertext, data_len);
        free(ciphertext);
    }

    mbedtls_platform_zeroize(tag, sizeof(tag));

    return crypto_error(
        vm,
        "AES-GCM: Mbed TLS operation failed"
    );
}


/*
 * AES-GCM decryption.
 */
static uc_value_t *
aes_gcm_decrypt(
    uc_vm_t *vm,
    size_t nargs,
    int key_bits
)
{
    uc_value_t *data_v = uc_fn_arg(0);
    uc_value_t *key_v  = uc_fn_arg(1);
    uc_value_t *iv_v   = uc_fn_arg(2);
    uc_value_t *tag_v  = uc_fn_arg(3);
    uc_value_t *aad_v  = uc_fn_arg(4);

    const unsigned char *data;
    const unsigned char *key;
    const unsigned char *iv;
    const unsigned char *tag;
    const unsigned char *aad = NULL;

    size_t data_len;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    size_t aad_len = 0;

    mbedtls_gcm_context ctx;
    unsigned char *plaintext = NULL;

    uc_value_t *result = NULL;
    int ret;

    mbedtls_gcm_init(&ctx);

    if (get_string(data_v, &data, &data_len) ||
        get_string(key_v, &key, &key_len) ||
        get_string(iv_v, &iv, &iv_len) ||
        get_string(tag_v, &tag, &tag_len)) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: invalid arguments"
        );
    }

    if (key_bits == 128) {
        if (key_len != 16) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-128-GCM: key must be 16 bytes"
            );
        }
    }
    else {
        if (key_len != 32) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-256-GCM: key must be 32 bytes"
            );
        }
    }

    if (iv_len == 0) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: IV must not be empty"
        );
    }

    if (aad_v) {
        if (ucv_type(aad_v) != UC_STRING) {
            mbedtls_gcm_free(&ctx);

            return crypto_error(
                vm,
                "AES-GCM: AAD must be a string"
            );
        }

        aad = (const unsigned char *)ucv_string_get(aad_v);
        aad_len = ucv_string_length(aad_v);
    }

    /* A truncated or oversized tag cannot authenticate: yield null. */
    if (tag_len < 12 || tag_len > 16) {
        mbedtls_gcm_free(&ctx);

        return NULL;
    }

    plaintext = malloc(data_len ? data_len : 1);

    if (!plaintext) {
        mbedtls_gcm_free(&ctx);

        return crypto_error(
            vm,
            "AES-GCM: out of memory"
        );
    }

    ret = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        key,
        (unsigned int)key_bits
    );

    if (ret != 0)
        goto error;

    /*
     * This performs authentication as part of decryption.
     */
    ret = mbedtls_gcm_auth_decrypt(
        &ctx,
        data_len,
        iv,
        iv_len,
        aad,
        aad_len,
        tag,
        tag_len,
        data,
        plaintext
    );

    if (ret != 0) {
        mbedtls_platform_zeroize(plaintext, data_len);
        free(plaintext);
        mbedtls_gcm_free(&ctx);

        /* Authentication failure yields null. */
        return NULL;
    }

    mbedtls_gcm_free(&ctx);

    result = ucv_string_new_length(
        (const char *)plaintext,
        data_len
    );

    mbedtls_platform_zeroize(plaintext, data_len);
    free(plaintext);

    return result;

error:
    mbedtls_gcm_free(&ctx);

    if (plaintext) {
        mbedtls_platform_zeroize(plaintext, data_len);
        free(plaintext);
    }

    return crypto_error(
        vm,
        "AES-GCM: Mbed TLS operation failed"
    );
}


/*
 * CBC.
 */

static uc_value_t *
uc_aes128_cbc_encrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_cbc_crypt(vm, nargs, 128, 0);
}


static uc_value_t *
uc_aes128_cbc_decrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_cbc_crypt(vm, nargs, 128, 1);
}


static uc_value_t *
uc_aes256_cbc_encrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_cbc_crypt(vm, nargs, 256, 0);
}


static uc_value_t *
uc_aes256_cbc_decrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_cbc_crypt(vm, nargs, 256, 1);
}


/*
 * GCM.
 */

static uc_value_t *
uc_aes128_gcm_encrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_gcm_encrypt(vm, nargs, 128);
}


static uc_value_t *
uc_aes128_gcm_decrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_gcm_decrypt(vm, nargs, 128);
}


static uc_value_t *
uc_aes256_gcm_encrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_gcm_encrypt(vm, nargs, 256);
}


static uc_value_t *
uc_aes256_gcm_decrypt(uc_vm_t *vm, size_t nargs)
{
    return aes_gcm_decrypt(vm, nargs, 256);
}


static const uc_function_list_t global_fns[] = {
    { "aes128_cbc_encrypt", uc_aes128_cbc_encrypt },
    { "aes128_cbc_decrypt", uc_aes128_cbc_decrypt },
    { "aes256_cbc_encrypt", uc_aes256_cbc_encrypt },
    { "aes256_cbc_decrypt", uc_aes256_cbc_decrypt },

    { "aes128_gcm_encrypt", uc_aes128_gcm_encrypt },
    { "aes128_gcm_decrypt", uc_aes128_gcm_decrypt },
    { "aes256_gcm_encrypt", uc_aes256_gcm_encrypt },
    { "aes256_gcm_decrypt", uc_aes256_gcm_decrypt },
};


void
uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
    uc_function_list_register(scope, global_fns);
}
