#pragma once
#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include "../utils/item.hpp"
#include "../utils/compare.cpp"

using namespace std;

char *tail_compress(const char *lastleft, const char *firstright, int len_ll, int len_fr) {
    int prefixlen = get_common_prefix_len(lastleft, firstright, len_ll, len_fr);
    if (len_fr > prefixlen) {
        prefixlen++;
    }
    char *separator = new char[prefixlen + 1];
    strncpy(separator, firstright, prefixlen);
    separator[prefixlen] = '\0';

    return separator;
}
char *tail_compress(char *leftprefix, char *rightprefix, const char *leftsuffix, const char *rightsuffix, int len_ll, int len_fr) {
    char *left = new char[len_ll + 1];
    char *right = new char[len_fr + 1];
    memcpy(left, leftprefix, PV_SIZE);
    memcpy(left + PV_SIZE, leftsuffix, len_ll - PV_SIZE);
    memcpy(right, rightprefix, PV_SIZE);
    memcpy(right + PV_SIZE, rightsuffix, len_fr - PV_SIZE);
    left[len_ll] = '\0'; right[len_fr] = '\0';
    return tail_compress(left, right, len_ll, len_fr);
}

int tail_compress_length(const char *lastleft, const char *firstright, int len_ll, int len_fr) {
#ifdef KN
int idx = 0;
for (int i = 0; i < min(len_ll, len_fr) / PV_SIZE; i++) {
    for (int j = 3; j >= 0; j--) {
        if (lastleft[i * PV_SIZE + j] != firstright[i * PV_SIZE + j]) return len_fr > idx ? ++idx : idx;
        idx++;
    }
}
return len_fr > idx ? ++idx : idx;
#else
    int prefixlen = get_common_prefix_len(lastleft, firstright, len_ll, len_fr);
    if (len_fr > prefixlen) {
        prefixlen++;
    }
    return prefixlen;
#endif
}

int tail_compress_length(char *leftprefix, char *rightprefix, const char *leftsuffix, const char *rightsuffix, int len_ll, int len_fr) {
    char *left = new char[len_ll + 1];
    char *right = new char[len_fr + 1];
    memcpy(left, leftprefix, PV_SIZE);
    memcpy(left + PV_SIZE, leftsuffix, len_ll - PV_SIZE);
    memcpy(right, rightprefix, PV_SIZE);
    memcpy(right + PV_SIZE, rightsuffix, len_fr - PV_SIZE);
    left[len_ll] = '\0'; right[len_fr] = '\0';
    return tail_compress_length(left, right, len_ll, len_fr);
}

int head_compression_find_prefix_length(Item *low, Item *high) {
    int prefixlen = get_common_prefix_len(low->addr, high->addr, low->size, high->size);
    if (high->size == prefixlen + 1 && low->size >= prefixlen + 1 && ((high->addr)[prefixlen] - (low->addr)[prefixlen] == 1)) {
        prefixlen++;
    }
    return prefixlen;
}
