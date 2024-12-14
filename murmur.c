#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#define MURMUR_VAULT ".murmur"
#define BLOCKS_DIR ".murmur/blocks"
#define SNAPSHOTS_DIR ".murmur/snapshots"
#define INDEX_DIR ".murmur/index"

// Placeholder for MurmurHash function
uint32_t murmurhash(const void *key, int len, uint32_t seed);

// Initialize the deduplication vault
void init_vault() {
    if (mkdir(MURMUR_VAULT, 0755) == -1) {
        perror("Failed to create .murmur vault");
        exit(1);
    }
    mkdir(BLOCKS_DIR, 0755);
    mkdir(SNAPSHOTS_DIR, 0755);
    mkdir(INDEX_DIR, 0755);

    printf("Initialized Murmur vault in %s\n", MURMUR_VAULT);
}

// Store a file by splitting it into deduplicated blocks
void store_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    char buffer[4096]; // 4KB block size
    size_t bytes_read;

    // Create or update the file's block mapping
    char index_path[256];
    snprintf(index_path, sizeof(index_path), "%s/index/%s.index", MURMUR_VAULT, filename);
    FILE *index_file = fopen(index_path, "w");
    if (!index_file) {
        perror("Failed to create index file");
        fclose(file);
        return;
    }

    // Process each block in the file
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        uint32_t hash = murmurhash(buffer, bytes_read, 42); // Generate block hash
        char block_path[256];
        snprintf(block_path, sizeof(block_path), "%s/blocks/%08x", MURMUR_VAULT, hash);

        // Deduplicate block globally
        if (access(block_path, F_OK) == -1) {
            FILE *block_file = fopen(block_path, "wb");
            if (!block_file) {
                perror("Failed to create block file");
                fclose(file);
                fclose(index_file);
                return;
            }
            fwrite(buffer, 1, bytes_read, block_file);
            fclose(block_file);
            printf("Stored new block: %08x\n", hash);
        } else {
            printf("Block already exists: %08x\n", hash);
        }

        // Map the block to the file
        fprintf(index_file, "%08x\n", hash);
    }

    fclose(file);
    fclose(index_file);
    printf("File '%s' stored successfully.\n", filename);
}

// Create a snapshot of the current state
void create_snapshot() {
    time_t now = time(NULL);
    char snapshot_name[64];
    snprintf(snapshot_name, sizeof(snapshot_name), "%s/snapshots/snapshot_%ld.snap", MURMUR_VAULT, now);

    FILE *snapshot_file = fopen(snapshot_name, "w");
    if (!snapshot_file) {
        perror("Failed to create snapshot file");
        return;
    }

    DIR *dir = opendir(INDEX_DIR);
    if (!dir) {
        perror("Failed to read index directory");
        fclose(snapshot_file);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue; // Skip hidden files

        // Write file-to-block mapping
        fprintf(snapshot_file, "FILE %s\n", entry->d_name);

        char index_path[256];
        snprintf(index_path, sizeof(index_path), "%s/index/%s", MURMUR_VAULT, entry->d_name);

        FILE *index_file = fopen(index_path, "r");
        if (index_file) {
            char hash[64];
            while (fgets(hash, sizeof(hash), index_file)) {
                fprintf(snapshot_file, "BLOCK %s", hash); // Include newlines
            }
            fclose(index_file);
        }
    }

    closedir(dir);
    fclose(snapshot_file);
    printf("Snapshot created: %s\n", snapshot_name);
}

// Restore files from a snapshot
void restore_snapshot(const char *snapshot_name) {
    char snapshot_path[256];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshots/%s", MURMUR_VAULT, snapshot_name);

    FILE *snapshot_file = fopen(snapshot_path, "r");
    if (!snapshot_file) {
        perror("Failed to open snapshot file");
        return;
    }

    char line[256];
    char current_file[256];
    FILE *output_file = NULL;

    while (fgets(line, sizeof(line), snapshot_file)) {
        if (strncmp(line, "FILE ", 5) == 0) {
            if (output_file) fclose(output_file);

            sscanf(line + 5, "%255s", current_file);
            char *dot_index = strstr(current_file, ".index");
            if (dot_index) *dot_index = '\0';

            output_file = fopen(current_file, "wb");
            if (!output_file) {
                perror("Failed to create restored file");
                continue;
            }
            printf("Restoring file: %s\n", current_file);
        } else if (strncmp(line, "BLOCK ", 6) == 0) {
            char block_hash[64];
            sscanf(line + 6, "%s", block_hash);

            char block_path[256];
            snprintf(block_path, sizeof(block_path), "%s/blocks/%s", MURMUR_VAULT, block_hash);

            FILE *block_file = fopen(block_path, "rb");
            if (block_file) {
                char buffer[4096];
                size_t bytes_read;
                while ((bytes_read = fread(buffer, 1, sizeof(buffer), block_file)) > 0) {
                    fwrite(buffer, 1, bytes_read, output_file);
                }
                fclose(block_file);
            } else {
                perror("Failed to open block file");
            }
        }
    }

    if (output_file) fclose(output_file);
    fclose(snapshot_file);
    printf("Snapshot restored: %s\n", snapshot_name);
}

// Placeholder for the MurmurHash implementation
uint32_t murmurhash(const void *key, int len, uint32_t seed) {
    uint32_t hash = seed;
    const uint8_t *data = (const uint8_t *)key;

    for (int i = 0; i < len; ++i) {
        hash = hash ^ data[i];
        hash *= 0x5bd1e995;
        hash ^= hash >> 15;
    }

    return hash;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: murmur <command>\n");
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {
        init_vault();
    } else if (strcmp(argv[1], "store") == 0 && argc == 3) {
        store_file(argv[2]);
    } else if (strcmp(argv[1], "snapshot") == 0) {
        create_snapshot();
    } else if (strcmp(argv[1], "restore") == 0 && argc == 3) {
        restore_snapshot(argv[2]);
    } else {
        printf("Unknown command: %s\n", argv[1]);
    }

    return 0;
}