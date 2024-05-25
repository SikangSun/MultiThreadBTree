#pragma once
#include "node.h"
// #include "../utils/config.h"
void word_conv_store(const char* src, const char* dest);
long word_cmp_loop(char* suffix, int suffixlen, char* key, int keylen);
char* string_conv(const char* key, int keylen, int cutoff);


#define NewPage() (new char[MAX_SIZE_IN_BYTES])
#define SetEmptyPage(p) memset(p, 0, sizeof(char) * MAX_SIZE_IN_BYTES)
#define BufTop(nptr) (nptr->base + nptr->space_top)


#define PageOffset(nptr, off) (char *)(nptr->base + off)


#define UpdateBase(node, newbase) \
    {                             \
        delete[] node->base;      \
        node->base = newbase;     \
    }


#define UpdatePtrs(node, newptrs, num)  \
    {                                   \
        for (int i = 0; i < num; i++)   \
            node->ptrs[i] = newptrs[i]; \
        node->ptr_cnt = num;            \
    }


#define InsertNode(nptr, pos, newnode)                         \
    {                                                          \
        nptr->ptrs.emplace(nptr->ptrs.begin() + pos, newnode); \
        nptr->ptr_cnt += 1;                                    \
    }
/*
================For standard==============
*/
#define UpdatePfxItem(nptr, addr, size, newallo)      \
    {                                                 \
        delete nptr->prefix;                          \
        nptr->prefix = new Item(addr, size, newallo); \
    }


#define GetHeaderStd(nptr, i) (Stdhead *)(nptr->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(Stdhead))


inline void InsertKeyStd(Node *nptr, int pos, const char *k, uint16_t klen) {
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderStd(nptr, i), GetHeaderStd(nptr, i - 1), sizeof(Stdhead));
    }
    // Set the new header
    Stdhead *header = GetHeaderStd(nptr, pos);
    header->key_offset = nptr->space_top;
    #ifdef PV
        if (klen > PV_SIZE) {
            memcpy(BufTop(nptr), k + PV_SIZE, klen - PV_SIZE);
            nptr->space_top += klen - PV_SIZE + 1;
        }
        else {
            strcpy(BufTop(nptr), "\0");
            nptr->space_top += 1;
        }
        memset(header->key_prefix, 0, PV_SIZE);
        memcpy(header->key_prefix, k, PV_SIZE);
    #else
        strcpy(BufTop(nptr), k);
        nptr->space_top += klen + 1;
    #endif


    header->key_len = klen;
    nptr->size += 1;
}


// TODO:
inline void RemoveKeyStd(Node *nptr, int pos, const char *k, uint16_t klen) {
    strcpy(BufTop(nptr), k);
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderStd(nptr, i), GetHeaderStd(nptr, i - 1), sizeof(Stdhead));
    }
    // Set the new header
    Stdhead *header = GetHeaderStd(nptr, pos);
    header->key_offset = nptr->space_top;
    header->key_len = klen;
    nptr->space_top += klen + 1;
    nptr->size += 1;
}


// with cutoff
inline void CopyToNewPageStd(Node *nptr, int low, int high, char *newbase, uint16_t cutoff, uint16_t &top) {//cutoff is potential head_comp ignored bytes
    for (int i = low; i < high; i++) {
        int newidx = i - low;
        Stdhead *oldhead = GetHeaderStd(nptr, i);
        Stdhead *newhead = (Stdhead *)(newbase + MAX_SIZE_IN_BYTES
                                       - (newidx + 1) * sizeof(Stdhead));
        int key_len = oldhead->key_len;

        #ifdef PV
            char *presuf = new char[key_len + 1 + PV_SIZE]; //extract entire key, invariant holds
            memset(presuf, 0, key_len + 1 + PV_SIZE); //pad for copy purposes
            memcpy(presuf, oldhead->key_prefix, PV_SIZE);
            if (oldhead->key_len > PV_SIZE) memcpy(presuf + PV_SIZE, PageOffset(nptr, oldhead->key_offset), key_len - PV_SIZE);

            int nullbytenum = cutoff;

            for (int i = 0; i < key_len; i++) {
                if (presuf[i] == '\0') nullbytenum++;
            }
            int truncate = (nullbytenum / PV_SIZE) * PV_SIZE;
            int newkeylen = oldhead->key_len - truncate;
            newhead->key_len = newkeylen;
            newhead->key_offset = top;
            memset(newhead->key_prefix, 0, PV_SIZE); //cutoff can't be longer than length right? yes
            memcpy(newhead->key_prefix, presuf + cutoff, PV_SIZE); //at least 4 bytes

            int sufLength = newkeylen - PV_SIZE; if (sufLength < 0) sufLength = 0;
            memcpy(newbase + top, presuf + cutoff + PV_SIZE, sufLength + 1); //ends at nullbyte, even if 0

            top += sufLength + 1; //if key can fit into prefix, then there will be a null_byte place holder
            delete[] presuf;
        #else
            strcpy(BufTop(nptr), k);
            strcpy(newbase + top, PageOffset(nptr, oldhead->key_offset) + cutoff);
            newhead->key_len = oldhead->key_len - cutoff;
            newhead->key_offset = top;
            top += newhead->key_len + 1;
        #endif
        // if (newhead->key_len > 32)
        //     cout << "wrong update" << endl;
    }
}


inline void word_conv_store(char* src, char* dest) { //int length only for now
    char c3 = src[3]; //supports in-place
    char c2 = src[2];
    dest[3] = src[0];
    dest[0] = c3;
    dest[2] = src[1];
    dest[1] = c2;
}


inline char* string_conv(const char* key, int &keylen) {//unnormalized to normalized
    int mod = keylen % PV_SIZE;
    int oglen = keylen;
    keylen = keylen + (mod > 0 ? PV_SIZE - mod : 0);

    char *result = new char[keylen + PV_SIZE + 1]; //pad zeroes
    memset(result, 0, keylen + 1 + PV_SIZE);
    memcpy(result, key, oglen);
    char *pointer = result;
    for (int i = 0; i < keylen; i += PV_SIZE, pointer += PV_SIZE) {
        word_conv_store(pointer, pointer);
    }

    return result;
}

// inline char* round_fixed_length(const char* key, int &keylen) {//input is normalized but breaks invariant
//     int mod = keylen % PV_SIZE;
//     if (mod == 0) return (char*)key;
//     int oglen = keylen;
//     keylen = keylen + mod;
//     char *result = new char[keylen + 1];
//     memset(result, 0, keylen + 1);
//     memcpy(result, key, oglen); //only last word needs word_conv
//     word_conv_store((result + keylen - PV_SIZE), (result + keylen - PV_SIZE));
//     delete[] key;
//     return result;
// }

inline char* construct_promotekey(char* prefix, char* suffix, int &keylen) {//assume header is always larger than keylen b/c compression
    int mod = keylen % PV_SIZE;
    int nullbytenum = mod > 0 ? PV_SIZE - mod : 0;
    int roundedkeylen = keylen + nullbytenum;
    char *result = new char[roundedkeylen + 1];
    memset(result, 0, roundedkeylen + 1);
    memcpy(result, prefix, PV_SIZE);
    if (roundedkeylen > PV_SIZE) memcpy(result + PV_SIZE, suffix, roundedkeylen - PV_SIZE);
    for (int i = 0; i < nullbytenum; i++) {
        result[roundedkeylen - PV_SIZE + i] = '\0'; //overwrite last word with null bytes
    } 
    keylen = roundedkeylen;
    return result;
}

inline char* construct_promotekey_head(Node* cursor, char* prefix, char* suffix, int &keylen) {//assume header is always larger than keylen b/c compression
    int size = cursor->prefix->size;
    int mod = (size + keylen) % PV_SIZE;
    int nullbytenum = mod > 0 ? PV_SIZE - mod : 0;
    int roundedkeylen = keylen + nullbytenum;
    char *result = new char[roundedkeylen + 1];
    memset(result, 0, roundedkeylen + 1);
    memcpy(result, cursor->prefix->addr, size);
    memcpy(result + size, prefix, PV_SIZE);
    if (roundedkeylen > PV_SIZE + size) memcpy(result + size + PV_SIZE, suffix, roundedkeylen - PV_SIZE - size);
    //copy until the end length
    for (int i = 0; i < nullbytenum; i++) {
        result[roundedkeylen - PV_SIZE + i] = '\0';
    } 
    keylen = roundedkeylen;
    return result;
}


inline long word_cmp(Stdhead* header,const char* key, int keylen, Node *cursor) {
    int cmp = *(int*)key - *(int*)header->key_prefix;
    if (cmp == 0 && keylen > PV_SIZE && header->key_len > PV_SIZE) {
        char *suffix = PageOffset(cursor, header->key_offset);
        key += PV_SIZE;
        for (int idx = 0; idx < min((int)header->key_len - PV_SIZE, keylen - PV_SIZE); idx += 4) {
            cmp = *(int *)(key + idx) - *(int*)(suffix + idx);
            if (cmp != 0) return cmp;
        }
        cmp = keylen - header->key_len;
    }
    else if (cmp == 0) return keylen - header->key_len;
    /* Contents are equal up to the smallest length. */
    return cmp;
}


/*
===============For DB2=============
*/
#define NewPageDB2() (new char[MAX_SIZE_IN_BYTES + DB2_PFX_MAX_SIZE])
#define SetEmptyPageDB2(p) memset(p, 0, sizeof(char) * (MAX_SIZE_IN_BYTES + DB2_PFX_MAX_SIZE))


#define GetKeyDB2(result, off) (char *)(result->base + off)
#define GetPfxDB2(result, off) (char *)(result->base + MAX_SIZE_IN_BYTES + off)
#define GetHeaderInPageDB2(result, i) (DB2head *)(result->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(DB2head))
#define GetPfxInPageDB2(result, i) (DB2pfxhead *)(result->base + (MAX_SIZE_IN_BYTES + DB2_PFX_MAX_SIZE) - (i + 1) * sizeof(DB2pfxhead))


#define PfxTop(nptr) (nptr->base + MAX_SIZE_IN_BYTES + nptr->pfx_top)


#define GetHeaderDB2(nptr, i) (DB2head *)(nptr->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(DB2head))


#define GetHeaderDB2pfx(nptr, i) (DB2pfxhead *)(nptr->base + MAX_SIZE_IN_BYTES + DB2_PFX_MAX_SIZE - (i + 1) * sizeof(DB2pfxhead))


#define PfxOffset(node, off) (char *)(node->base + MAX_SIZE_IN_BYTES + off)


inline void InsertPfxDB2(NodeDB2 *nptr, int pos, const char *p, uint16_t plen, uint16_t low, uint16_t high) {
    char *temp = PfxTop(nptr);
    memcpy(temp, p, sizeof(char) * plen);
    temp[plen] = '\0';
    // shift the headers
    for (int i = nptr->pfx_size; i > pos; i--) {
        memcpy(GetHeaderDB2pfx(nptr, i), GetHeaderDB2pfx(nptr, i - 1), sizeof(DB2pfxhead));
    }
    // Set the new header
    DB2pfxhead *header = GetHeaderDB2pfx(nptr, pos);
    header->pfx_offset = nptr->pfx_top;
    header->pfx_len = plen;
    header->low = low;
    header->high = high;
    nptr->pfx_top += plen + 1;
    nptr->pfx_size += 1;
}


inline void InsertKeyDB2(NodeDB2 *nptr, int pos, const char *k, uint16_t klen) {
    strcpy(BufTop(nptr), k);
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderDB2(nptr, i), GetHeaderDB2(nptr, i - 1), sizeof(DB2head));
    }
    // Set the new header
    DB2head *header = GetHeaderDB2(nptr, pos);
    header->key_offset = nptr->space_top;
    header->key_len = klen;
    nptr->space_top += klen + 1;
    nptr->size += 1;
}


inline void CopyToNewPageDB2(NodeDB2 *nptr, int low, int high, char *newbase, uint16_t &top) {
    for (int i = low; i < high; i++) {
        int newidx = i - low;
        DB2head *oldhead = GetHeaderDB2(nptr, i);
        DB2head *newhead = (DB2head *)(newbase + MAX_SIZE_IN_BYTES
                                       - (newidx + 1) * sizeof(DB2head));
        strncpy(newbase + top, PageOffset(nptr, oldhead->key_offset), oldhead->key_len);
        newhead->key_len = oldhead->key_len;
        newhead->key_offset = top;
        top += oldhead->key_len + 1;
    }
}


// for a single base without a node scope
#define WriteKeyDB2Page(base, memusage, pos, k, klen, plen)                                     \
    {                                                                                           \
        strcpy(base + memusage, k + plen);                                                      \
        DB2head *head = (DB2head *)(newbase + MAX_SIZE_IN_BYTES - (pos + 1) * sizeof(DB2head)); \
        head->key_len = klen - plen;                                                            \
        head->key_offset = memusage;                                                            \
        memusage += head->key_len + 1;                                                          \
    }


// Only write to the end of prefix page
// the input pfxbase mush be based on node->base + max_size_in_byte
#define WritePfxDB2Page(base, pfxtop, pfxitem, pfxsize)                                                                      \
    {                                                                                                                        \
        strcpy(base + MAX_SIZE_IN_BYTES + pfxtop, pfxitem.prefix.addr);                                                      \
        DB2pfxhead *head = (DB2pfxhead *)(base + MAX_SIZE_IN_BYTES + DB2_PFX_MAX_SIZE - (pfxsize + 1) * sizeof(DB2pfxhead)); \
        head->pfx_offset = pfx_top;                                                                                          \
        head->pfx_len = pfxitem.prefix.size;                                                                                 \
        head->low = pfxitem.low;                                                                                             \
        head->high = pfxitem.high;                                                                                           \
        pfxtop += pfxitem.prefix.size + 1;                                                                                   \
        pfxsize++;                                                                                                           \
    }
/*
===============For WiredTiger=============
*/


// Get the ith header, i starts at 0
#define GetHeaderWT(nptr, i) (WThead *)(nptr->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(WThead))


// The prefix should be cutoff before calling this
inline void InsertKeyWT(NodeWT *nptr, int pos, const char *k, int klen, int plen) {
    strcpy(BufTop(nptr), k);
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderWT(nptr, i), GetHeaderWT(nptr, i - 1), sizeof(WThead));
    }
    // Set the new header
    WThead *header = GetHeaderWT(nptr, pos);
    header->key_offset = nptr->space_top;
    header->key_len = (uint16_t)klen;
    header->pfx_len = (uint16_t)plen;
#ifdef WTCACHE
    header->initialized = false;
#endif
    nptr->space_top += klen + 1;
    nptr->size += 1;
}


inline void CopyToNewPageWT(NodeWT *nptr, int low, int high, char *newbase, int &top) {
    for (int i = low; i < high; i++) {
        int newidx = i - low;
        WThead *oldhead = GetHeaderWT(nptr, i);
        WThead *newhead = (WThead *)(newbase + MAX_SIZE_IN_BYTES
                                     - (newidx + 1) * sizeof(WThead));
        strncpy(newbase + top, PageOffset(nptr, oldhead->key_offset), oldhead->key_len);
        newhead->key_len = (uint16_t)oldhead->key_len;
        newhead->key_offset = top;
        newhead->pfx_len = (uint16_t)oldhead->pfx_len;
        top += oldhead->key_len + 1;
    }
}


#define GetHeaderMyISAM(nptr, i) (MyISAMhead *)(nptr->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(MyISAMhead))


inline void InsertKeyMyISAM(NodeMyISAM *nptr, int pos, const char *k, int klen, int plen) {
    strcpy(BufTop(nptr), k);
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderMyISAM(nptr, i), GetHeaderMyISAM(nptr, i - 1), sizeof(MyISAMhead));
    }
    // Set the new header
    MyISAMhead *header = GetHeaderMyISAM(nptr, pos);
    header->key_offset = nptr->space_top;
    header->key_len = (uint16_t)klen;
    header->pfx_len = (uint16_t)plen;
    nptr->space_top += klen + 1;
    nptr->size += 1;
}


inline void CopyToNewPageMyISAM(NodeMyISAM *nptr, int low, int high, char *newbase, int &top) {
    for (int i = low; i < high; i++) {
        int newidx = i - low;
        MyISAMhead *oldhead = GetHeaderMyISAM(nptr, i);
        MyISAMhead *newhead = (MyISAMhead *)(newbase + MAX_SIZE_IN_BYTES
                                             - (newidx + 1) * sizeof(MyISAMhead));
        strncpy(newbase + top, PageOffset(nptr, oldhead->key_offset), oldhead->key_len);
        newhead->key_len = (uint16_t)oldhead->key_len;
        newhead->key_offset = top;
        newhead->pfx_len = (uint16_t)oldhead->pfx_len;
        top += oldhead->key_len + 1;
    }
}


#define GetHeaderPkB(nptr, i) (PkBhead *)(nptr->base + MAX_SIZE_IN_BYTES - (i + 1) * sizeof(PkBhead))


// the k and klen here should always be the fullkey
inline void InsertKeyPkB(NodePkB *nptr, int pos, const char *k, uint16_t klen, uint16_t plen) {
    strcpy(BufTop(nptr), k);
    // shift the headers
    for (int i = nptr->size; i > pos; i--) {
        memcpy(GetHeaderPkB(nptr, i), GetHeaderPkB(nptr, i - 1), sizeof(PkBhead));
    }
    // Set the new header
    PkBhead *header = GetHeaderPkB(nptr, pos);
    header->key_offset = nptr->space_top;
    header->key_len = klen;
    header->pfx_len = plen;
    if (plen < klen) {
        int pk_len = min(klen - plen, PKB_LEN);
        strncpy(header->pk, k + plen, pk_len);
        header->pk[pk_len] = '\0';
        header->pk_len = pk_len;
    }
    else {
        memset(header->pk, 0, sizeof(header->pk));
        header->pk_len = 0;
    }


    nptr->space_top += klen + 1;
    nptr->size += 1;
}


inline void CopyToNewPagePkB(NodePkB *nptr, int low, int high, char *newbase, int &top) {
    for (int i = low; i < high; i++) {
        int newidx = i - low;
        PkBhead *oldhead = GetHeaderPkB(nptr, i);
        PkBhead *newhead = (PkBhead *)(newbase + MAX_SIZE_IN_BYTES
                                       - (newidx + 1) * sizeof(PkBhead));
        strncpy(newbase + top, PageOffset(nptr, oldhead->key_offset), oldhead->key_len);
        memcpy(newhead, oldhead, sizeof(PkBhead));
        // offset is different
        newhead->key_offset = top;
        top += oldhead->key_len + 1;
    }
}

