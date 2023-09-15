#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <iostream>
#include <unordered_map>
#include <string.h>
#include <memory>
#include <cstring>
#include "../include/config.h"

using namespace std;

int MAX_NODE_SIZE = 4;

// Key represented as <key, {rid list}>
// str representation of rids for easy comparison and prefix compression
// if other approaches are used
struct Item {
    char *addr;
    uint8_t size;
    bool newallocated = false;
    Item() {
        // this works for wt, myisam, pkb and splitkey,
        // temporarily fetch a key
        newallocated = false;
    }
    Item(bool allocated) {
        // this works for std compression: prefix, l/hkey
        addr = new char[1];
        addr[0] = '\0';
        size = 0;
        newallocated = true;
    }
    Item(Item &old) {
        addr = new char[old.size + 1];
        strcpy(addr, old.addr);
        size = old.size;
        newallocated = true;
    }
    Item(char *p, uint8_t l, bool allo) {
        addr = p;
        size = l;
        newallocated = allo;
    }
    ~Item() {
        if (newallocated) {
            delete addr;
        }
    }
    Item &operator=(Item &old) {
        addr = old.addr;
        size = old.size;
        newallocated = false;
        return *this;
    }
};

class Key {
public:
    vector<string> ridList;
    string value;
    Key(string value, int rid);
    void addRecord(int rid);
    int getSize();
};

class Key_c {
public:
    vector<int> ridList;
    char *value;
    Key_c(char *value, int rid);
    void addRecord(int rid);
    int getSize();
    void update_value(string s);
};

// BP-std node

const char MAXHIGHKEY[] = "infinity";

struct Stdhead {
    uint16_t key_offset;
    uint8_t key_len;
} __attribute__((packed));

class Node {
public:
    bool IS_LEAF;
    int size;
    char *base;
    uint16_t space_top;
    vector<Node *> ptrs;
    uint8_t ptr_cnt;

    Item *lowkey;
    Item *highkey;
    Item *prefix;
    Node *prev; // Prev node pointer
    Node *next; // Next node pointer
    Node();
    ~Node();
};

struct DB2head {
    uint16_t key_offset;
    uint8_t key_len;
} __attribute__((packed));

struct DB2pfxhead {
    uint16_t pfx_offset;
    uint8_t pfx_len;
    uint8_t low;
    uint8_t high;
} __attribute__((packed));

class NodeDB2 {
public:
    bool IS_LEAF;
    int size;
    int pfx_size;
    char *base;
    char *pfxbase;
    uint16_t space_top;
    uint16_t pfx_top;
    vector<NodeDB2 *> ptrs;
    uint8_t ptr_cnt;
    NodeDB2 *prev; // Prev node pointer
    NodeDB2 *next; // Next node pointer
    NodeDB2();
    ~NodeDB2();
};

// Key with prefix and suffix encoding
// Duplicates represented as <key, {rid list}>
#ifdef DUPKEY
class KeyMyISAM {
public:
    string value;
    vector<string> ridList;
    // Using a uchar equivalent from the MyISAM source code
    u_char *prefix;
    bool is1Byte;
    KeyMyISAM(string value, int prefix, int rid);
    KeyMyISAM(string value, int prefix, vector<string> ridList);
    int getPrefix();
    void setPrefix(int prefix);
    void addRecord(int rid);
    int getSize();
};

class NodeMyISAM {
public:
    bool IS_LEAF;
    vector<KeyMyISAM> keys;
    int size;
    vector<NodeMyISAM *> ptrs;
    NodeMyISAM *prev; // Prev node pointer
    NodeMyISAM *next; // Next node pointer
    NodeMyISAM();
    ~NodeMyISAM();
};
#else
struct MyISAMhead {
    uint16_t key_offset;
    uint8_t key_len;
    uint8_t pfx_len;
    /* We assume all the prefix are less than 128 Byte, so remove is1Byte in MyISAM
     *  May need to consider the case key/pfx_len in [128, 256)
     */
    // bool is1B;
} __attribute__((packed));

class NodeMyISAM {
public:
    bool IS_LEAF;
    int size;
    char *base;
    uint16_t space_top;

    vector<NodeMyISAM *> ptrs;
    NodeMyISAM *prev; // Prev node pointer
    NodeMyISAM *next; // Next node pointer
    uint16_t ptr_cnt;
    NodeMyISAM();
    ~NodeMyISAM();
};
#endif

#ifdef DUPKEY
// Duplicates represented as <key, {rid list}>
class KeyWT {
public:
    string value;
    vector<string> ridList;
    uint8_t prefix;
    bool isinitialized;
    string initialized_value;
    KeyWT(string value, uint8_t prefix, int rid);
    KeyWT(string value, uint8_t prefix, vector<string> ridList);
    void addRecord(int rid);
    int getSize();
};
#endif

// with no duplicate key
#ifdef WTCACHE
struct WThead {
    uint16_t key_offset;
    uint16_t initval_offset;
    uint8_t key_len;
    uint8_t init_len = 0;
    uint8_t pfx_len;
    bool initialized = false;
} __attribute__((packed));
#else
struct WThead {
    uint16_t key_offset;
    uint8_t key_len;
    uint8_t pfx_len;
} __attribute__((packed));
#endif

#ifndef DUPKEY
class NodeWT {
public:
    bool IS_LEAF;
    int size; // Total key number
    char *base;
    uint16_t space_top;
#ifdef WTCACHE
    uint16_t prefixstart; /* Best page prefix starting slot */
    uint16_t prefixstop;  /* Maximum slot to which the best page prefix applies */
#endif
    vector<NodeWT *> ptrs;
    NodeWT *prev; // Prev node pointer
    NodeWT *next; // Next node pointer
    uint16_t ptr_cnt;
    NodeWT();
    ~NodeWT();
};
#else
class NodeWT {
public:
    bool IS_LEAF;
    vector<KeyWT> keys;
    int size;
    vector<NodeWT *> ptrs;
    uint32_t prefixstart; /* Best page prefix starting slot */
    uint32_t prefixstop;  /* Maximum slot to which the best page prefix applies */
    NodeWT *prev;         // Prev node pointer
    NodeWT *next;         // Next node pointer
    NodeWT();
    ~NodeWT();
};
#endif

#ifdef DUPKEY
// Duplicates represented as <key, {rid list}>
class KeyPkB {
public:
    int16_t offset;
    char partialKey[PKB_LEN + 1];
    char *original;
    int pkLength;
    vector<string> ridList;
    KeyPkB(int offset, string value, char *ptr, int rid);
    KeyPkB(int offset, string value, char *ptr, vector<string> ridList);
    void addRecord(int rid);
    int getSize();
    void updateOffset(int offset);
};

class NodePkB {
public:
    bool IS_LEAF;
    vector<KeyPkB> keys;
    int size;
    vector<NodePkB *> ptrs;
    NodePkB *prev; // Prev node pointer
    NodePkB *next; // Next node pointer
    NodePkB();
    ~NodePkB();
};

#else
struct PkBhead {
    uint8_t pfx_len;
    uint8_t key_len;
    uint8_t pk_len;
    char pk[PKB_LEN + 1];
    uint16_t key_offset;
} __attribute__((packed));

class NodePkB {
public:
    bool IS_LEAF;
    int size;
    char *base;
    uint16_t space_top;
    vector<NodePkB *> ptrs;
    uint16_t ptr_cnt;
    NodePkB *prev; // Prev node pointer
    NodePkB *next; // Next node pointer
    NodePkB();
    ~NodePkB();
};
#endif

struct uncompressedKey { // for pkb
    string key;
    char *keyptr;
};

struct splitReturn {
    string promotekey;
    Node *left;
    Node *right;
};

struct splitReturn_new {
    Item promotekey;
    Node *left;
    Node *right;
};

struct splitReturnDB2 {
    Item promotekey;
    NodeDB2 *left;
    NodeDB2 *right;
};

struct splitReturnMyISAM {
    Item promotekey;
    NodeMyISAM *left;
    NodeMyISAM *right;
};

struct splitReturnWT {
    Item promotekey;
    NodeWT *left;
    NodeWT *right;
};

struct splitReturnPkB {
    Item promotekey;
    NodePkB *left;
    NodePkB *right;
};

struct nodeBounds {
    string lowerbound;
    string upperbound;
};

void printKeys(Node *node, bool compressed);
void printKeys_db2(NodeDB2 *node, bool compressed);
void printKeys_myisam(NodeMyISAM *node, bool compressed);
void printKeys_wt(NodeWT *node, bool compressed);
void printKeys_pkb(NodePkB *node, bool compressed);
