
#include "tree.h"
#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;
    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;
        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';
        ptr = null_byte + 1;
        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;
        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);
    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }
    *data_out = buffer;
    *len_out = offset;
    return 0;
}

static int write_tree_level(IndexEntry **entries, int count, int depth, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;
    int i = 0;
    while (i < count) {
        const char *path = entries[i]->path;
        const char *component = path;
        for (int d = 0; d < depth; d++) {
            const char *slash = strchr(component, '/');
            if (!slash) return -1;
            component = slash + 1;
        }
        const char *slash = strchr(component, '/');
        if (!slash) {
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i]->mode;
            te->hash = entries[i]->hash;
            strncpy(te->name, component, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            i++;
        } else {
            char dir_name[256];
            size_t dir_len = slash - component;
            if (dir_len >= sizeof(dir_name)) return -1;
            memcpy(dir_name, component, dir_len);
            dir_name[dir_len] = '\0';
            int j = i;
            while (j < count) {
                const char *p = entries[j]->path;
                const char *comp2 = p;
                for (int d = 0; d < depth; d++) {
                    const char *s = strchr(comp2, '/');
                    if (!s) { comp2 = NULL; break; }
                    comp2 = s + 1;
                }
                if (!comp2) break;
                const char *s2 = strchr(comp2, '/');
                if (!s2) break;
                size_t len2 = s2 - comp2;
                if (len2 != dir_len || memcmp(comp2, dir_name, dir_len) != 0) break;
                j++;
            }
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, depth + 1, &sub_id) < 0)
                return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = sub_id;
            strncpy(te->name, dir_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            i = j;
        }
    }
    void *data;
    size_t data_len;
    if (tree_serialize(&tree, &data, &data_len) < 0) return -1;
    int ret = object_write(OBJ_TREE, data, data_len, id_out);
    free(data);
    return ret;
}

int tree_from_index(ObjectID *id_out) {
    Index index;
    if (index_load(&index) < 0) return -1;
    if (index.count == 0) return -1;
    IndexEntry *entries[MAX_INDEX_ENTRIES];
    for (int i = 0; i < index.count; i++)
        entries[i] = &index.entries[i];
    return write_tree_level(entries, index.count, 0, id_out);
}
