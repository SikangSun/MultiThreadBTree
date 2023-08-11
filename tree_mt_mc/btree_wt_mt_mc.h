#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "node_mt_mc.cpp"
#include "util.cpp"
#include "../include/config.h"

using namespace std;

// BP tree
class BPTreeWTMT{
public:
	BPTreeWTMT(bool non_leaf_compression, bool suffix_compression);
	~BPTreeWTMT();
	int search(string_view);
	int searchRange(string, string);
	void insert(string);
	void getSize(NodeWT *, int &, int &, int &, int &, unsigned long &, int &);
	int getHeight(NodeWT *);
	NodeWT *getRoot();
	void setRoot(NodeWT *);
	void lockRoot(accessMode mode);
	void printTree(NodeWT *x, vector<bool> flag, bool compressed = false,
				   int depth = 0, bool isLast = false);
private:
	NodeWT *root;
	bool non_leaf_comp;
	bool suffix_comp;
	void insert_leaf(NodeWT *leaf, vector<NodeWT *> &parents, string key);
	void insert_nonleaf(NodeWT *node, vector<NodeWT *> &parents, int pos, splitReturnWT childsplit);
	int insert_binary(NodeWT *cursor, string_view key, int low, int high, size_t &skiplow);
	int search_binary(NodeWT *cursor, string_view key, int low, int high, size_t &skiplow);
	NodeWT* search_leaf_node(NodeWT *root, string_view key, vector<NodeWT *> &parents, size_t &skiplow);
	bool check_split_condition(NodeWT *node);
	int split_point(vector<KeyWT> allkeys);
	splitReturnWT split_nonleaf(NodeWT *node, vector<NodeWT *> parents, int pos, splitReturnWT childsplit);
	splitReturnWT split_leaf(NodeWT *node, vector<NodeWT *> &parents, string newkey);
	void bt_fetch_root(NodeWT *currRoot, vector<NodeWT *> &parents);
	NodeWT* scan_node(NodeWT *node, string key, size_t &skiplow);
	NodeWT* move_right(NodeWT *node, string key);
};