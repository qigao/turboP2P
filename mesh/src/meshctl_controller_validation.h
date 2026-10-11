#ifndef MESHCTL_CONTROLLER_VALIDATION_H
#define MESHCTL_CONTROLLER_VALIDATION_H

/* Shared CLI admission rules. These do not create a transport owner. */
int meshctl_controller_endpoint_valid(const char *endpoint);
int meshctl_controller_credential_file_valid(const char *path, int private_key);

#endif
