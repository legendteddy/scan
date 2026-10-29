#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_user(char *dst, const char *user) {
    strcpy(dst, user);
}

void build_response(char *dst, const char *name) {
    sprintf(dst, "hello %s", name);
}

void copy_payload(char *dst, const char *src, size_t supplied_len) {
    memcpy(dst, src, supplied_len);
}

int parse_count(const char *value) {
    return atoi(value);
}

int safe_copy_user(char *dst, size_t dst_size, const char *user) {
    if (dst_size == 0) return -1;
    int written = snprintf(dst, dst_size, "%s", user);
    return (written < 0 || (size_t)written >= dst_size) ? -1 : 0;
}

int safe_copy_payload(char *dst, size_t dst_size, const char *src, size_t supplied_len) {
    if (supplied_len > dst_size) return -1;
    memcpy(dst, src, supplied_len);
    return 0;
}
