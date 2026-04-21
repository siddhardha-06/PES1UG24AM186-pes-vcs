// pes.h — Core data structures and constants for PES-VCS
//
// This file is PROVIDED. Do not modify.

#ifndef PES_H
#define PES_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// ─── Constants ───────────────────────────────────────────────────────────────

#define HASH_SIZE 32        // SHA-256 produces 32 bytes
#define HASH_HEX_SIZE 64    // 32 bytes = 64 hex characters
#define PES_DIR ".pes"
#define OBJECTS_DIR ".pes/objects"
#define REFS_DIR ".pes/refs/heads"
#define INDEX_FILE ".pes/index"
#define HEAD_FILE ".pes/HEAD"

// ─── Object Types ────────────────────────────────────────────────────────────

typedef enum {
    OBJ_BLOB,    // File content
    OBJ_TREE,    // Directory listing
    OBJ_COMMIT   // Snapshot with metadata
} ObjectType;

// ─── Object Identifier ──────────────────────────────────────────────────────

typedef struct {
    uint8_t hash[HASH_SIZE];
} ObjectID;

// ─── Utility Functions (implement in object.c) ─────────────────────────────

// Convert a binary hash to a 64-character hex string (+ null terminator).
// hex_out must be at least HASH_HEX_SIZE + 1 bytes.
void hash_to_hex(const ObjectID *id, char *hex_out);

// Convert a 64-character hex string to a binary hash.
// Returns 0 on success, -1 if hex contains invalid characters.
int hex_to_hash(const char *hex, ObjectID *id_out);

// ─── Author Configuration ───────────────────────────────────────────────────
// PES-VCS reads the author name from the environment variable PES_AUTHOR.
// If unset, it defaults to "PES User <pes@localhost>".
//
// To set your name:
//   export PES_AUTHOR="Your Name <PESXUG24CS042>"

#define DEFAULT_AUTHOR "PES User <pes@localhost>"

static inline const char* pes_author(void) {
    const char *env = getenv("PES_AUTHOR");
    return (env && env[0]) ? env : DEFAULT_AUTHOR;
}

#endif // PES_H
