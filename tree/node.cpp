#pragma once
#include "node.h"
#include "node_inline.h"

// Constructor of Node
Node::Node() {
    // size = 0;
    // ptr_cnt = 0;
    // space_top = 0;
    base = NewPageStd();
    SetEmptyPageStd(base);

    StdPageHead *pagehead = (StdPageHead *)base;
    pagehead->size = 0;
    pagehead->ptr_cnt = 0;
    pagehead->space_top = 0;
    pagehead->lowkey = new Item(true);
    pagehead->highkey = new Item(); // this hk will be deallocated automatically
    pagehead->highkey->size = 0;
    pagehead->prefix = new Item(true);
    pagehead->IS_LEAF = true;
    // lowkey = new Item(true);
    // highkey = new Item(); // this hk will be deallocated automatically
    // // highkey->addr = new char[9];
    // // strcpy(highkey->addr, MAXHIGHKEY);
    // // highkey->newallocated = true;

    prev = nullptr;
    next = nullptr;
}

// Destructor of Node
Node::~Node() {
    StdPageHead *pagehead = (StdPageHead *)base;
    delete pagehead->lowkey;
    delete pagehead->highkey;
    delete pagehead->prefix;
    delete[] base;
}

//===============Below for DB2===========

NodeDB2::NodeDB2() {
    size = 0;
    pfx_size = 0;
    prev = nullptr;
    next = nullptr;
    ptr_cnt = 0;
    base = NewPageDB2();
    SetEmptyPageDB2(base);
    IS_LEAF = true;
    space_top = 0;
    pfx_top = 0;

    ptr_cnt = 0;
    InsertPfxDB2(this, 0, "", 0, 0, 0);
}

// Destructor of NodeDB2
NodeDB2::~NodeDB2() {
    delete[] base;
}

/*
==================For WiredTiger================
*/

NodeWT::NodeWT() {
    size = 0;
    prev = nullptr;
    next = nullptr;
    ptr_cnt = 0;

    prefixstart = 0;
    prefixstop = 0;

    base = NewPage();
    SetEmptyPage(base);
    space_top = 0;
    IS_LEAF = true;
}

// Destructor of NodeWT
NodeWT::~NodeWT() {
    delete[] base;
}

NodeMyISAM::NodeMyISAM() {
    size = 0;
    prev = nullptr;
    next = nullptr;
    ptr_cnt = 0;
    base = NewPage();
    SetEmptyPage(base);
    space_top = 0;
    IS_LEAF = true;
}

// Destructor of NodeMyISAM
NodeMyISAM::~NodeMyISAM() {
    delete[] base;
}

NodePkB::NodePkB() {
    size = 0;
    prev = nullptr;
    next = nullptr;
    ptr_cnt = 0;
    base = NewPage();
    SetEmptyPage(base);
    space_top = 0;
    IS_LEAF = true;
}

// Destructor of NodePkB
NodePkB::~NodePkB() {
    delete[] base;
}

void printKeys(Node *node, bool compressed) {
    StdPageHead *pagehead = (StdPageHead *)(node->base);
    if (compressed && pagehead->prefix->addr)
        cout << pagehead->prefix->addr << ": ";
    for (int i = 0; i < pagehead->size; i++) {
        Stdhead *head = GetHeaderStd(node, i);
        if (compressed && pagehead->prefix->addr) {
            cout << GetfromStd(node, head->key_offset) << ",";
        }
        else {
            cout << pagehead->prefix->addr << GetfromStd(node, head->key_offset) << ",";
        }
    }
}

void printKeys_db2(NodeDB2 *node, bool compressed) {
    for (int i = 0; i < node->pfx_size; i++) {
        DB2pfxhead *pfx = GetHeaderDB2pfx(node, i);
        if (compressed) {
            cout << "Prefix " << PfxOffset(node, pfx->pfx_offset) << ": ";
        }
        for (int l = pfx->low; l <= pfx->high; l++) {
            // Loop through rid list to print duplicates
            DB2head *head = GetHeaderDB2(node, l);
            if (compressed) {
                cout << PageOffset(node, head->key_offset) << ",";
            }
            else {
                cout << PfxOffset(node, pfx->pfx_offset) << PageOffset(node, head->key_offset) << ",";
            }
        }
    }
}

void printKeys_myisam(NodeMyISAM *node, bool compressed) {
    char *prev_key;
    char *curr_key;
    for (int i = 0; i < node->size; i++) {
        MyISAMhead *head = GetHeaderMyISAM(node, i);
        if (compressed || head->pfx_len == 0 || i == 0) {
            curr_key = PageOffset(node, head->key_offset);
            cout << unsigned(head->pfx_len) << ":" << curr_key << ",";
        }
        else {
            curr_key = new char[head->pfx_len + head->key_len + 1];
            strncpy(curr_key, prev_key, head->pfx_len);
            strcpy(curr_key + head->pfx_len, PageOffset(node, head->key_offset));
            cout << curr_key << ",";
        }
        prev_key = curr_key;
    }
}

void printKeys_wt(NodeWT *node, bool compressed) {
    char *prev_key;
    char *curr_key;
    for (int i = 0; i < node->size; i++) {
        WThead *head = GetHeaderWT(node, i);
        if (compressed || head->pfx_len == 0 || i == 0) {
            curr_key = PageOffset(node, head->key_offset);
            cout << unsigned(head->pfx_len) << ":" << curr_key << ",";
        }
        else {
            curr_key = new char[head->pfx_len + head->key_len + 1];
            strncpy(curr_key, prev_key, head->pfx_len);
            strcpy(curr_key + head->pfx_len, PageOffset(node, head->key_offset));
            cout << curr_key << ",";
        }

        prev_key = curr_key;
    }
}

void printKeys_pkb(NodePkB *node, bool compressed) {
    string curr_key;
    for (int i = 0; i < node->size; i++) {
        PkBhead *head = GetHeaderPkB(node, i);
        if (compressed) {
            cout << unsigned(head->pfx_len) << ":" << head->pk << "("
                 << PageOffset(node, head->key_offset) << ")"
                 << ",";
        }
        else {
            cout << PageOffset(node, head->key_offset) << ",";
        }
    }
}