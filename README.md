# pam_split_token

The purpose of this module is to simply split of an OTP token from the password received. It strips of the last "+" and following chars.

The `PAM_AUTHTOK` is modified to be only the first part of the received token (password) and it sets the environnment variable `PAM_SPLIT_TOKEN` to the chars following the + sign. The PAM_SPLIT_TOKEN can the be accessed with pam_getenv. The pam_exec.so module does this, but the pam_script.so module does not.

This was you can for example use this as backend element for Apache basic auth using mod_authnz_pam.

## Requirements

You must pass the parameter `forward_pass` to the module, so that it's allowed to pass on the modified `PAM_AUTHTOK`.

## options

If `PAM_AUTHTOK` is not set you can let the module ask for it if you provide the argument `query_missing_token`.
This way you can use it as the first module in an auth stack in PAM, eg. for SSH login.

## Examples

This is how you might use the module to receive the password+token combo in /etc/pam-d/sshd

```pam
auth    required                        pam_split_token.so forward_pass query_missing_token 
auth    required                        pam_exec.so /usr/share/libpam-script/pam_script_auth
@include common-auth
```

If the password is already provided, eg. in /etc/pam.d/apache you don't to query for the token,
as this could lead to errors.

```pam
auth    required                        pam_split_token.so forward_pass
auth    required                        pam_exec.so /usr/share/libpam-script/pam_script_auth
@include common-auth
```

The pam_script_auth could then contain something like:
```bash
#!/bin/bash

if [[ $PAM_SPLIT_TOKEN == "123456" ]]; then
  exit 0
fi
echo "Bad OTP: $PAM_SPLIT_TOKEN"
exit 1
```

This would succeed if the password `Sup3rS3cre7+123456` was provided.

2024-09-04: bahner
