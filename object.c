// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build the header string e.g. "blob 16"
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    // header_len does NOT include the null terminator, but we want to store it
    // The full object is: header + '\0' + data
    size_t full_len = header_len + 1 + len;  // +1 for the '\0'
    uint8_t *full = malloc(full_len);
    if (!full) return -1;

    memcpy(full, header, header_len);       // copy "blob 16"
    full[header_len] = '\0';               // the null separator
    memcpy(full + header_len + 1, data, len); // copy actual data

    // Step 2: Compute SHA-256 of the full object
    compute_hash(full, full_len, id_out);

    // Step 3: Deduplication — if object already exists, skip writing
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Step 4: Create shard directory .pes/objects/XX/
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[256];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755); // OK if it already exists

    // Step 5: Write to a temp file in the shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", shard_dir);
    int fd = mkstemp(tmp_path); // creates a unique temp file
    if (fd < 0) { free(full); return -1; }

    ssize_t written = write(fd, full, full_len);
    free(full);
    if (written != (ssize_t)full_len) { close(fd); unlink(tmp_path); return -1; }

    // Step 6: fsync the temp file — ensure data is on disk
    if (fsync(fd) < 0) { close(fd); unlink(tmp_path); return -1; }
    close(fd);

    // Step 7: Atomically rename temp file to final path
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    if (rename(tmp_path, final_path) < 0) { unlink(tmp_path); return -1; }

    // Step 8: fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Get the file path for this object
    char path[512];
    object_path(id, path, sizeof(path));

    // Step 2: Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0) { fclose(f); return -1; }

    uint8_t *buf = malloc(file_size);
    if (!buf) { fclose(f); return -1; }
    if ((long)fread(buf, 1, file_size, f) != file_size) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    // Step 3: Parse the header — find the '\0' separator
    uint8_t *null_pos = memchr(buf, '\0', file_size);
    if (!null_pos) { free(buf); return -1; }

    // Header is everything before the '\0'
    char header[64];
    size_t hdr_len = null_pos - buf;
    if (hdr_len >= sizeof(header)) { free(buf); return -1; }
    memcpy(header, buf, hdr_len);
    header[hdr_len] = '\0';

    // Parse type and size from header e.g. "blob 16"
    char type_str[16];
    size_t data_size;
    if (sscanf(header, "%15s %zu", type_str, &data_size) != 2) {
        free(buf); return -1;
    }

    if      (strcmp(type_str, "blob")   == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree")   == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else { free(buf); return -1; }

    // Step 4: Verify integrity — recompute hash and compare to expected
    ObjectID computed;
    compute_hash(buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf); return -1; // corrupted!
    }

    // Step 5 & 6: Copy the data portion (after the '\0') into output buffer
    uint8_t *data_start = null_pos + 1;
    size_t actual_data_len = file_size - (hdr_len + 1);
    if (actual_data_len != data_size) { free(buf); return -1; }

    *data_out = malloc(actual_data_len);
    if (!*data_out) { free(buf); return -1; }
    memcpy(*data_out, data_start, actual_data_len);
    *len_out = actual_data_len;

    free(buf);
    return 0;
}
