// tree.h — Tree object interface
//
// A tree object represents a directory snapshot. Each entry maps a name
// to either a blob (file) or another tree (subdirectory), along with
// the file mode (permissions + type).

#ifndef TREE_H
#define TREE_H

#include "pes.h"

#define MAX_TREE_ENTRIES 1024

typedef struct {
    uint32_t mode;          // 100644 (regular), 100755 (executable), 040000 (directory)
    ObjectID hash;          // SHA-256 of the blob or subtree
    char name[256];         // Entry name (filename or directory name, no path separators)
} TreeEntry;

typedef struct {
    TreeEntry entries[MAX_TREE_ENTRIES];
    int count;
} Tree;

// Parse raw tree object data (as read from the object store) into a Tree struct.
int tree_parse(const void *data, size_t len, Tree *tree_out);

// Serialize a Tree struct into raw bytes suitable for object_write(OBJ_TREE, ...).
// Entries MUST be sorted by name before serialization.
// Caller must free(*data_out).
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out);

// Build a Tree from the current index contents.
// This is what `pes commit` uses: it reads the index and constructs a tree
// hierarchy that represents the staged snapshot. For nested paths
// (e.g., "src/main.c"), this function must create subtrees.
// Writes all tree objects to the object store.
// Returns the root tree's ObjectID in *id_out.
int tree_from_index(ObjectID *id_out);

#endif // TREE_H
