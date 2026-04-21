// index.h — Staging area (index) interface
//
// The index is a text file (.pes/index) that tracks which files are
// staged for the next commit. It maps file paths to their blob hashes
// and stores metadata for fast change detection.

#ifndef INDEX_H
#define INDEX_H

#include "pes.h"

#define MAX_INDEX_ENTRIES 10000

typedef struct {
    uint32_t mode;          // File mode (100644, 100755, etc.)
    ObjectID hash;          // SHA-256 of the staged blob
    uint64_t mtime_sec;     // Last modification time (seconds since epoch)
    uint32_t size;          // File size in bytes at time of staging
    char path[512];         // Relative path from repo root (e.g., "src/main.c")
} IndexEntry;

typedef struct {
    IndexEntry entries[MAX_INDEX_ENTRIES];
    int count;
} Index;

// Load the index from .pes/index into memory.
// If the file does not exist (no files staged yet), initializes an empty index.
int index_load(Index *index);

// Save the index to .pes/index using atomic write (temp file + rename).
int index_save(const Index *index);

// Stage a file: read its contents, write as a blob, update/add index entry.
int index_add(Index *index, const char *path);

// Remove a file from the index (unstage it).
int index_remove(Index *index, const char *path);

// Find an entry by path. Returns pointer to the entry, or NULL if not found.
IndexEntry* index_find(Index *index, const char *path);

// Print the status of the working directory compared to the index and HEAD.
// Output format:
//   Staged changes:
//     staged:     <path>
//
//   Unstaged changes:
//     modified:   <path>
//     deleted:    <path>
//
//   Untracked files:
//     untracked:  <path>
int index_status(const Index *index);

#endif // INDEX_H
