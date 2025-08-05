# murmur

murmur is a lightweight, user-space block-level deduplication and snapshot tool designed for efficient file backup and versioning.

It works by splitting files into blocks, hashing them using a simplified MurmurHash algorithm, compressing them (zlib), and storing only unique blocks. Snapshots record the file/directory structure and their block composition, allowing for restoration or remote sync.

## Features

- Deduplicates identical blocks across files
- Compresses stored blocks
- Supports recursive directory backup
- Fast snapshot creation and restoration
- Rsync-based remote push/pull of data
- Portable C implementation (tested on macOS and FreeBSD, should work on any POSIX system)

## Vault Structure

Creates .murmur directory inside current working directory with:

- blocks/: deduplicated, compressed file blocks
- snapshots/: snapshots of directory state
- index/: block lists for each file

## Usage 

		# Initialize murmur vault
		$ murmur init

		# Store a file or directory (recursively)
		$ murmur store myfolder/

		# Create snapshot
		$ murmur snapshot

		# Restore snapshot
		$ murmur restore snapshot_1691223456.snap

		# Send data to remote backup (via rsync)
		$ murmur send user@host:/remote/backup

		# Fetch snapshot and restore
		$ murmur fetch user@host:/remote/backup snapshot_1691223456.snap


## Limitations

- No rolling checksum: block boundaries are fixed-size (4096 bytes)
- Only works on regular files and directories
- Snapshot names are timestamped automatically
- Currently single-threaded

## License

MIT
