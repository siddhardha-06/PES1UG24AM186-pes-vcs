// pes.c — CLI entry point and command dispatch
//
// This file is PROVIDED. Do not modify.

#include "pes.h"
#include "index.h"
#include "commit.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// ─── PROVIDED: Command Implementations ──────────────────────────────────────

// Usage: pes init
void cmd_init(void) {
    if (mkdir(PES_DIR, 0755) != 0 && access(PES_DIR, F_OK) != 0) {
        fprintf(stderr, "error: failed to create %s\n", PES_DIR);
        return;
    }
    mkdir(OBJECTS_DIR, 0755);
    mkdir(".pes/refs", 0755);
    mkdir(REFS_DIR, 0755);

    if (access(HEAD_FILE, F_OK) != 0) {
        FILE *f = fopen(HEAD_FILE, "w");
        if (f) {
            fprintf(f, "ref: refs/heads/main\n");
            fclose(f);
        }
    }

    printf("Initialized empty PES repository in %s/\n", PES_DIR);
}

// Usage: pes add <file>...
void cmd_add(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pes add <file>...\n");
        return;
    }

    Index index;
    if (index_load(&index) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        return;
    }

    for (int i = 2; i < argc; i++) {
        if (index_add(&index, argv[i]) != 0) {
            fprintf(stderr, "error: failed to add '%s'\n", argv[i]);
        }
    }
}

// Usage: pes status
void cmd_status(void) {
    Index index;
    if (index_load(&index) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        return;
    }
    index_status(&index);
}

// Usage: pes commit -m <message>
void cmd_commit(int argc, char *argv[]) {
    if (argc < 4 || strcmp(argv[2], "-m") != 0) {
        fprintf(stderr, "error: commit requires a message (-m \"message\")\n");
        return;
    }

    const char *message = argv[3];
    ObjectID commit_id;
    if (commit_create(message, &commit_id) != 0) {
        fprintf(stderr, "error: commit failed\n");
        return;
    }

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&commit_id, hex);
    printf("Committed: %.12s... %s\n", hex, message);
}

// Callback for commit_walk used by cmd_log.
static void print_commit(const ObjectID *id, const Commit *commit, void *ctx) {
    (void)ctx;
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    printf("commit %s\n", hex);
    printf("Author: %s\n", commit->author);
    printf("Date:   %llu\n", (unsigned long long)commit->timestamp);
    printf("\n    %s\n\n", commit->message);
}

// Usage: pes log
void cmd_log(void) {
    if (commit_walk(print_commit, NULL) != 0) {
        fprintf(stderr, "No commits yet.\n");
    }
}

// ─── PROVIDED: Command dispatch ─────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: pes <command> [args]\n");
        fprintf(stderr, "\nCommands:\n");
        fprintf(stderr, "  init            Create a new PES repository\n");
        fprintf(stderr, "  add <file>...   Stage files for commit\n");
        fprintf(stderr, "  status          Show working directory status\n");
        fprintf(stderr, "  commit -m <msg> Create a commit from staged files\n");
        fprintf(stderr, "  log             Show commit history\n");
        return 1;
    }

    const char *cmd = argv[1];

    if      (strcmp(cmd, "init") == 0)     cmd_init();
    else if (strcmp(cmd, "add") == 0)      cmd_add(argc, argv);
    else if (strcmp(cmd, "status") == 0)   cmd_status();
    else if (strcmp(cmd, "commit") == 0)   cmd_commit(argc, argv);
    else if (strcmp(cmd, "log") == 0)      cmd_log();
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        fprintf(stderr, "Run 'pes' with no arguments for usage.\n");
        return 1;
    }

    return 0;
}
