#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

/*
 * Helper function to check if a specific argument is provided in pam.conf
 */
int has_argument(int argc, const char **argv, const char *arg) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], arg) == 0) {
            return 1; // Argument found
        }
    }
    return 0; // Argument not found
}

/*
 * PAM authentication function.
*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *authtok;
    int pam_ret;

    // Check if the "query_missing_token" argument is provided
    int query_missing_token = has_argument(argc, argv, "query_missing_token");

    // Retrieve the current PAM_AUTHTOK (the user-supplied password + token)
    pam_ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
    if (pam_ret != PAM_SUCCESS || authtok == NULL || strlen(authtok) == 0) {
        // Only prompt if query_missing_token argument is provided
        if (query_missing_token) {
            // Allocate a buffer for the input
            char *input = NULL;

            // Prompt the user for the password+token
            pam_ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &input, "Password+Token: ");
            if (pam_ret != PAM_SUCCESS || input == NULL) {
                pam_syslog(pamh, LOG_ERR, "Failed to prompt for Password+Token.");
                return PAM_AUTH_ERR;
            }

            authtok = input; // Use this as the authtok
        } else {
            pam_syslog(pamh, LOG_ERR, "PAM_AUTHTOK is empty and query_missing_token is not set.");
            return PAM_AUTH_ERR; // Fail if no authtok and no query_missing_token argument
        }
    }

    // Ensure the authtok is not unreasonably long
    if (strlen(authtok) > PAM_MAX_RESP_SIZE) {
        pam_syslog(pamh, LOG_ERR, "PAM_AUTHTOK is too long.");
        return PAM_AUTH_ERR;
    }

    // Find the position of the last '+' character
    char *plus_pos = strrchr(authtok, '+');
    if (plus_pos == NULL) {
        pam_syslog(pamh, LOG_ERR, "No '+' found in PAM_AUTHTOK.");
        return PAM_AUTH_ERR;
    }

    // Split the authtok into password and token
    size_t password_len = plus_pos - authtok;
    char *password = strndup(authtok, password_len); // Copy only the password part
    if (password == NULL) {
        pam_syslog(pamh, LOG_ERR, "Failed to allocate memory for password.");
        return PAM_BUF_ERR;
    }

    // Ensure the token is not empty
    if (*(plus_pos + 1) == '\0') {
        pam_syslog(pamh, LOG_ERR, "No token found after the last '+'.");
        free(password);
        return PAM_AUTH_ERR;
    }

    const char *token = plus_pos + 1;  // Token part starts after '+'

    // Set the modified password (without the token) back into PAM_AUTHTOK
    pam_ret = pam_set_item(pamh, PAM_AUTHTOK, password);
    if (pam_ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to set PAM_AUTHTOK.");
        free(password);
        return PAM_AUTH_ERR;
    }

    // Allocate memory for the environment variable to hold the token
    size_t token_env_size = strlen("PAM_SPLIT_TOKEN=") + strlen(token) + 1; // +1 for null terminator
    char *token_env = malloc(token_env_size);
    if (!token_env) {
        pam_syslog(pamh, LOG_ERR, "Failed to allocate memory for token environment variable.");
        free(password);
        return PAM_BUF_ERR;
    }

    snprintf(token_env, token_env_size, "PAM_SPLIT_TOKEN=%s", token);

    // Set PAM_SPLIT_TOKEN environment variable to the token
    pam_ret = pam_putenv(pamh, token_env);
    if (pam_ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to set PAM_SPLIT_TOKEN environment variable.");
        free(password);
        free(token_env);
        return PAM_AUTH_ERR;
    }

    // Log success
    pam_syslog(pamh, LOG_INFO, "PAM_AUTHTOK and PAM_SPLIT_TOKEN set successfully.");

    // Clean up
    free(password);
    free(token_env);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
