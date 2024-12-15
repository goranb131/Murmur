#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <zlib.h>

#define MURMUR_VAULT ".murmur"
#define BLOCKS_DIR ".murmur/blocks"
#define SNAPSHOTS_DIR ".murmur/snapshots"
#define INDEX_DIR ".murmur/index"

// MurmurHash function placeholder
uint32_t murmurhash(const void *key, int len, uint32_t seed);

// inits the whole vault structure
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

// store a file splitting it into deduplicated blocks
void store_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    char buffer[4096]; // 4KB block size
    size_t bytes_read;

    // this is where we record which blocks belong to the file
    char index_path[256];
    snprintf(index_path, sizeof(index_path), "%s/index/%s.index", MURMUR_VAULT, filename);
    FILE *index_file = fopen(index_path, "w");
    if (!index_file) {
        perror("Failed to create index file");
        fclose(file);
        return;
    }

    // read file block by block
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // generate block hash
        uint32_t hash = murmurhash(buffer, bytes_read, 42); 
        char block_path[256];
        snprintf(block_path, sizeof(block_path), "%s/blocks/%08x", MURMUR_VAULT, hash);

        // deduplication happens here, no duplicate blocks saved
        if (access(block_path, F_OK) == -1) {
            // compress block before saving
            char compressed[4096];
            uLongf compressed_size = sizeof(compressed);
            if (compress((Bytef *)compressed, &compressed_size, (const Bytef *)buffer, bytes_read) != Z_OK) {
                perror("Compression failed");
                fclose(file);
                fclose(index_file);
                return;
            }

            // write compressed block to the vault
            FILE *block_file = fopen(block_path, "wb");
            if (!block_file) {
                perror("Failed to create block file");
                fclose(file);
                fclose(index_file);
                return;
            }

            fwrite(compressed, 1, compressed_size, block_file);
            fclose(block_file);
            printf("Stored new compressed block: %08x (original: %lu bytes, compressed: %lu bytes)\n",
                   hash, bytes_read, compressed_size);
        } else {
            printf("Block already exists: %08x\n", hash);
        }

        // record block hash to the index file
        fprintf(index_file, "%08x\n", hash);
    }

    fclose(file);
    fclose(index_file);
    printf("File '%s' stored successfully.\n", filename);
}

// snapshot
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
        if (entry->d_name[0] == '.') continue; // skip hidden files

        // write each files index to the snapshot
        fprintf(snapshot_file, "FILE %s\n", entry->d_name);

        char index_path[256];
        snprintf(index_path, sizeof(index_path), "%s/index/%s", MURMUR_VAULT, entry->d_name);

        FILE *index_file = fopen(index_path, "r");
        if (index_file) {
            char hash[64];
            while (fgets(hash, sizeof(hash), index_file)) {
                fprintf(snapshot_file, "BLOCK %s", hash); // include newlines
            }
            fclose(index_file);
        }
    }

    closedir(dir);
    fclose(snapshot_file);
    printf("Snapshot created: %s\n", snapshot_name);
}

// restore from a snapshot
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
                // read compressed block
                char compressed[4096];
                char decompressed[4096];
                size_t compressed_size = fread(compressed, 1, sizeof(compressed), block_file);
                fclose(block_file);

                // decompress block
                uLongf decompressed_size = sizeof(decompressed);
                if (uncompress((Bytef *)decompressed, &decompressed_size, (const Bytef *)compressed, compressed_size) != Z_OK) {
                    perror("Decompression failed");
                    continue;
                }

                // write decompressed data to output file
                fwrite(decompressed, 1, decompressed_size, output_file);
            } else {
                perror("Failed to open block file");
            }
        }
    }

    if (output_file) fclose(output_file);
    fclose(snapshot_file);
    printf("Snapshot restored: %s\n", snapshot_name);
}

// send to remote
void send_to_remote(const char *remote_path) {
    char command[512];
    snprintf(command, sizeof(command), "rsync -av %s/ %s/", SNAPSHOTS_DIR, remote_path);
    if (system(command) == 0) {
        printf("Snapshots sent to remote: %s\n", remote_path);
    } else {
        printf("Failed to send snapshots to remote.\n");
    }

    snprintf(command, sizeof(command), "rsync -av %s/ %s/blocks/", BLOCKS_DIR, remote_path);
    if (system(command) == 0) {
        printf("Blocks sent to remote: %s\n", remote_path);
    } else {
        printf("Failed to send blocks to remote.\n");
    }
}

// fetch snapshot and blocks from remote
void fetch_from_remote(const char *remote_path, const char *snapshot_name) {
    char command[512];

    // fetch snapshot
    snprintf(command, sizeof(command), "rsync -av %s/%s %s/", remote_path, snapshot_name, SNAPSHOTS_DIR);
    if (system(command) == 0) {
        printf("Snapshot %s fetched from remote.\n", snapshot_name);
    } else {
        printf("Failed to fetch snapshot from remote.\n");
        return;
    }

    // fetch blocks
    snprintf(command, sizeof(command), "rsync -av %s/blocks/ %s/blocks/", remote_path, MURMUR_VAULT);
    if (system(command) == 0) {
        printf("Blocks fetched from remote.\n");
    } else {
        printf("Failed to fetch blocks from remote.\n");
    }

    restore_snapshot(snapshot_name);
}

// MurmurHash implementation
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