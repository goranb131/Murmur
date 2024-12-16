#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <zlib.h>
#include <errno.h>

#define MURMUR_VAULT ".murmur"
#define BLOCKS_DIR ".murmur/blocks"
#define SNAPSHOTS_DIR ".murmur/snapshots"
#define INDEX_DIR ".murmur/index"

// simplified MurmurHash
uint32_t murmurhash(const void *key, int len, uint32_t seed);

// 
void verify_dir(const char *path) {
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s", path);

    char *p = temp_path + 1; // no first '/'
    while ((p = strchr(p, '/')) != NULL) {
        *p = '\0';
        mkdir(temp_path, 0755); // create intermediate directories
        *p++ = '/';
    }
    mkdir(temp_path, 0755); // create full path
}

// is path a part of "vault"?
int is_in_vault(const char *path) {
    return (strstr(path, MURMUR_VAULT) != NULL);
}

// init vault structure
void init_vault() {
    verify_dir(MURMUR_VAULT);
    verify_dir(BLOCKS_DIR);
    verify_dir(SNAPSHOTS_DIR);
    verify_dir(INDEX_DIR);

    printf("[INFO] Initialized murmur vault in %s\n", MURMUR_VAULT);
}

// recursively store files and directories
void store_file(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) == -1) {
        perror("[ERROR] Failed to stat path");
        return;
    }

    if (S_ISDIR(path_stat.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            perror("[ERROR] Failed to open directory");
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
            store_file(full_path);
        }
        closedir(dir);
    } else if (S_ISREG(path_stat.st_mode)) {
        printf("[DEBUG] Storing file: %s\n", path);

        FILE *file = fopen(path, "rb");
        if (!file) {
            perror("[ERROR] Failed to open file");
            return;
        }

        char buffer[4096];
        size_t bytes_read;

        // .index file path
        char index_path[512];
        snprintf(index_path, sizeof(index_path), "%s/%s.index", INDEX_DIR, path);

        // verify parent directories of the .index file exist
        char parent_dir[512];
        snprintf(parent_dir, sizeof(parent_dir), "%s", index_path);
        char *last_slash = strrchr(parent_dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            verify_dir(parent_dir);
            *last_slash = '/';
        }

        FILE *index_file = fopen(index_path, "w");
        if (!index_file) {
            perror("[ERROR] Failed to create index file");
            fclose(file);
            return;
        }

        // processing file blocks
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            uint32_t hash = murmurhash(buffer, bytes_read, 42);
            char block_path[256];
            snprintf(block_path, sizeof(block_path), "%s/%08x", BLOCKS_DIR, hash);

            if (access(block_path, F_OK) == -1) {
                char compressed[4096];
                uLongf compressed_size = sizeof(compressed);
                if (compress((Bytef *)compressed, &compressed_size, (const Bytef *)buffer, bytes_read) != Z_OK) {
                    perror("[ERROR] Compression failed");
                    fclose(file);
                    fclose(index_file);
                    return;
                }

                FILE *block_file = fopen(block_path, "wb");
                if (!block_file) {
                    perror("[ERROR] Failed to create block file");
                    fclose(file);
                    fclose(index_file);
                    return;
                }

                fwrite(compressed, 1, compressed_size, block_file);
                fclose(block_file);
                printf("[INFO] Stored new compressed block: %08x\n", hash);
            } else {
                printf("[DEBUG] Block already exists: %08x\n", hash);
            }

            fprintf(index_file, "%08x\n", hash);
        }

        fclose(file);
        fclose(index_file);
        printf("[INFO] File '%s' stored successfully\n", path);
    }
}

// recursive traversing of directory and log to snapshot
void snapshot_recursive(FILE *snapshot_file, const char *relative_path) {
    DIR *dir = opendir(relative_path);
    if (!dir) {
        perror("[ERROR] Failed to open directory");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char entry_path[512];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", relative_path, entry->d_name);

        if (is_in_vault(entry_path)) {
            printf("[DEBUG] Skipping vault file: %s\n", entry_path);
            continue;
        }

        struct stat path_stat;
        if (stat(entry_path, &path_stat) == -1) {
            perror("[ERROR] Failed to stat path");
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            fprintf(snapshot_file, "DIR %s\n", entry_path);
            printf("[DEBUG] Added directory to snapshot: %s\n", entry_path);
            snapshot_recursive(snapshot_file, entry_path);
        } else if (S_ISREG(path_stat.st_mode)) {
            fprintf(snapshot_file, "FILE %s\n", entry_path);
            printf("[DEBUG] Added file to snapshot: %s\n", entry_path);

            char index_path[512];
            snprintf(index_path, sizeof(index_path), "%s/%s.index", INDEX_DIR, entry_path);

            FILE *index_file = fopen(index_path, "r");
            if (index_file) {
                char hash[64];
                while (fgets(hash, sizeof(hash), index_file)) {
                    fprintf(snapshot_file, "BLOCK %s", hash);
                    printf("[DEBUG] Added block to snapshot: %s\n", hash);
                }
                fclose(index_file);
            } else {
                printf("[WARNING] No index file found for: %s\n", entry_path);
            }
        }
    }

    closedir(dir);
}

void create_snapshot() {
    time_t now = time(NULL);
    char snapshot_name[512];
    snprintf(snapshot_name, sizeof(snapshot_name), "%s/snapshot_%ld.snap", SNAPSHOTS_DIR, now);

    FILE *snapshot_file = fopen(snapshot_name, "w");
    if (!snapshot_file) {
        perror("[ERROR] Failed to create snapshot file");
        return;
    }

    printf("[DEBUG] Starting snapshot creation: %s\n", snapshot_name);
    snapshot_recursive(snapshot_file, ".");
    fclose(snapshot_file);

    printf("[INFO] Snapshot created: %s\n", snapshot_name);
}

// restore files and directories from snapshot
void restore_snapshot(const char *snapshot_name) {
    char snapshot_path[512];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s", SNAPSHOTS_DIR, snapshot_name);

    FILE *snapshot_file = fopen(snapshot_path, "r");
    if (!snapshot_file) {
        perror("[ERROR] Failed to open snapshot file");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), snapshot_file)) {
        if (strncmp(line, "DIR ", 4) == 0) {
            char dir_path[512];
            sscanf(line + 4, "%s", dir_path);
            mkdir(dir_path, 0755);
        } else if (strncmp(line, "FILE ", 5) == 0) {
            char file_path[512];
            sscanf(line + 5, "%s", file_path);

            char original_file[512];
            snprintf(original_file, sizeof(original_file), "%s", file_path);

            FILE *file_out = fopen(original_file, "wb");
            if (!file_out) {
                perror("[ERROR] Failed to create restored file");
                continue;
            }

            char index_path[512];
            snprintf(index_path, sizeof(index_path), "%s/%s.index", INDEX_DIR, file_path);

            FILE *index_file = fopen(index_path, "r");
            if (!index_file) {
                perror("[ERROR] Failed to open index file");
                fclose(file_out);
                continue;
            }

            char hash[64];
            while (fgets(hash, sizeof(hash), index_file)) {
                hash[strcspn(hash, "\n")] = '\0';

                char block_path[512];
                snprintf(block_path, sizeof(block_path), "%s/%s", BLOCKS_DIR, hash);

                FILE *block_file = fopen(block_path, "rb");
                if (!block_file) {
                    perror("[ERROR] Failed to open block file");
                    continue;
                }

                char compressed[4096];
                char decompressed[4096];
                size_t compressed_size = fread(compressed, 1, sizeof(compressed), block_file);
                fclose(block_file);

                uLongf decompressed_size = sizeof(decompressed);
                if (uncompress((Bytef *)decompressed, &decompressed_size, (const Bytef *)compressed, compressed_size) != Z_OK) {
                    perror("[ERROR] Decompression failed");
                    continue;
                }

                fwrite(decompressed, 1, decompressed_size, file_out);
            }

            fclose(index_file);
            fclose(file_out);
        }
    }

    fclose(snapshot_file);
    printf("[INFO] Snapshot restored: %s\n", snapshot_name);
}

void send_to_remote(const char *remote_path) {
    char command[512];

    // send blocks
    snprintf(command, sizeof(command), "rsync -av --progress %s/ %s/blocks/", BLOCKS_DIR, remote_path);
    printf("[DEBUG] Sending blocks to remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to send blocks to remote.\n");
        return;
    }
    printf("[INFO] Blocks sent successfully.\n");

    // send snapshots
    snprintf(command, sizeof(command), "rsync -av --progress %s/ %s/snapshots/", SNAPSHOTS_DIR, remote_path);
    printf("[DEBUG] Sending snapshots to remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to send snapshots to remote.\n");
        return;
    }
    printf("[INFO] Snapshots sent successfully.\n");

    // send indexes
    snprintf(command, sizeof(command), "rsync -av --progress %s/ %s/index/", INDEX_DIR, remote_path);
    printf("[DEBUG] Sending indexes to remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to send indexes to remote.\n");
        return;
    }
    printf("[INFO] Indexes sent successfully.\n");
}

void fetch_from_remote(const char *remote_path, const char *snapshot_name) {
    char command[512];

    // fetch blocks
    snprintf(command, sizeof(command), "rsync -av --progress %s/blocks/ %s", remote_path, BLOCKS_DIR);
    printf("[DEBUG] Fetching blocks from remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to fetch blocks from remote.\n");
        return;
    }
    printf("[INFO] Blocks fetched successfully.\n");

    // fetch snapshots
    snprintf(command, sizeof(command), "rsync -av --progress %s/snapshots/ %s", remote_path, SNAPSHOTS_DIR);
    printf("[DEBUG] Fetching snapshots from remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to fetch snapshots from remote.\n");
        return;
    }
    printf("[INFO] Snapshots fetched successfully.\n");

    // fetch indexes
    snprintf(command, sizeof(command), "rsync -av --progress %s/index/ %s", remote_path, INDEX_DIR);
    printf("[DEBUG] Fetching indexes from remote: %s\n", remote_path);
    if (system(command) != 0) {
        printf("[ERROR] Failed to fetch indexes from remote.\n");
        return;
    }
    printf("[INFO] Indexes fetched successfully.\n");

    // restore specified snapshot
    char snapshot_path[512];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s", SNAPSHOTS_DIR, snapshot_name);
    printf("[DEBUG] Restoring snapshot: %s\n", snapshot_path);
    restore_snapshot(snapshot_name);
}

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
    } else if (strcmp(argv[1], "send") == 0 && argc == 3) {
        send_to_remote(argv[2]);
    } else if (strcmp(argv[1], "fetch") == 0 && argc == 4) {
        fetch_from_remote(argv[2], argv[3]);
    } else {
        printf("Unknown command: %s\n", argv[1]);
    }

    return 0;
}