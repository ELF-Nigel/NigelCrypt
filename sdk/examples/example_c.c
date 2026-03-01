#include "nigelcrypt/nigelcrypt_c.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Configure strict mode (optional)
    nc_strict_mode sm = {0};
    sm.enabled = 1;
    sm.require_aad = 1;
    sm.require_binding = 1;
    sm.require_algorithm = NC_ALG_AES256_GCM;
    nc_set_strict_mode(&sm);

    // Create secure string
    nc_secure_string* s = nc_secure_string_new();
    if (!s) {
        printf("failed to create secure string\n");
        return 1;
    }

    const char* aad = "aad:example";
    const char* msg = "runtime-only";
    nc_status st = nc_secure_string_encrypt(
        s,
        msg, 12,
        aad, 11,
        NC_ALG_AES256_GCM,
        NC_BIND_PROCESS
    );
    if (st != NC_OK) {
        printf("encrypt failed: %s\n", nc_status_message(st));
        nc_secure_string_free(s);
        return 1;
    }

    char out[64] = {0};
    nc_decrypt_options opt = {0};
    opt.buffer = NC_BUFFER_VIRTUAL_LOCKED;
    opt.require_aad = 1;
    opt.zero_on_failure = 1;

    size_t wrote = 0;
    st = nc_secure_string_decrypt_to(s, out, sizeof(out), aad, 11, &opt, &wrote);
    if (st != NC_OK) {
        printf("decrypt failed: %s\n", nc_status_message(st));
        nc_secure_string_free(s);
        return 1;
    }

    printf("decrypted: %s\n", out);

    nc_secure_string_free(s);
    return 0;
}
