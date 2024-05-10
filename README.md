# WatDFS Manual

## 1. Design Choices and Key Functionalities Implementation

### Keeping track of States

1. Client-side (store in userdata)

Inside `watdfs_cli_init`, create a client_meta that is used to store client-side global caching information and returns a pointer to a client_meta struct. 

```cpp
struct file_meta {
    int flags;     
    int fh;
    time_t tc;
    int server_fh;
};

struct client_meta {
    char *path_to_cache;
    time_t cache_interval;
    std::unordered_map<std::string, struct file_meta*> cache;
};
```

client_meta

- Path to my cache directory (used in get_full_path to retrieve to full path of a file)
- Cache_internal -> records the freshness interval of a cached file, used to determine if a cache entry is timed-out
- Cache -> Keeps track of files on the client-side whose counterparts have not been released on the server side.
- The key of cache is the full path of the file
- The value is a pointer to `struct file_meta`, which stores
    - `flags` -> The flags of the file
    - `fh` ->The file handler of the client-side file
    - `Tc` -> time the cache entry was last validated by the client
    - `server_fh` -> server_side file handler, used when trying to get server-side file handler while server-side file is already opened (could not make a open rpc call)

1. Server-side

```cpp
enum file_mode { RD_MODE, WT_MODE };

std::unordered_map<std::string, rw_lock_t*> file_lock_mapping;
std::unordered_map<std::string, enum file_mode > file_mode_mapping;
pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;
```

- `file_lock_mapping` (protected by `lock_mutex`) -> maps relative path of file to the rw_lock_t on the file
- `file_mode_mapping` (protected by `map_mutex`) -> maps relative path of file to the mode of the file (`RD_MODE` –> `O_RDONLY`, `WT_MODE` – `WRONLY` and `RDWR`)

### Copying Files from Client to Server (Upload)

When the client modifies or release a file (via write, truncate, or utimensat operations), it checks if the file needs to be uploaded based on the freshness condition. If the file is opened in RDONLY mode or if the cache doesn’t time-out or its last modification time is the same as the server, we don’t peform the upload.

Steps to upload:

1. Perform lock rpc call to acquire the file lock on the server-side in `RW_WRITE_LOCK` mode (first initialize the lock if there’s no such entry in the `file_lock_mapping`)
2. Call `stat` to get client-side file attributes
3. Create a `fuse_file_info server_fi` that will store the flags and file handler to be passed to following rpc calls to the server
4. Call `geattr_rpc` to get server-side file attributes
    1. if retcode < 0, the file doesn’t exist on server-side, will call `mknod_rpc` and `open_rpc` with `RDWR` mode since we need to write to server-side file (stored in `server_fi`)
    2. Otherwise, the file is already opened on the server-side, we will retrieve the server-side file flags and file handler from our userdata (stored in `server_fi`)
5. Open the file locally with O_RDONLY and read locally file content to a buffer
6. Make a truncate rpc call to server to resize server-side file to the same size as client-side file
7. Make a write rpc call to write file content in the buffer to server-side file
8. Call utimesat_rpc to update timestamps of the file
9. Close local file
10. Make release_rpc call to close the file. Before closing, server will check if the mode of the file is O_RDONLY. If not, will change the mode to O_RDONLY in `file_mode_mapping` 
11. Make unlock rpc call to release the lock on the file.

### Copying Files from Server to Client Downloading

Transferring files from server to client happens when the client is trying to access and modify a file that is not in its cache or if the cache entry for that file is invalidated.

Steps to download:

1. Call `lock_rpc` to acquire the file lock on the server-side in `RW_READ_LOCK` mode (first initialize the lock if there’s no such entry in the file_lock_mapping)
2. Call `geattr_rpc` to get server-side file attributes into a `server_statbuf` stat
3.  Initialize a `char* buf` with size of `server_statbuf.st_size`
4. Call open with flag `O_RDWR` mode, create and sets the permission of the newly created file if the file doesn’t already exist
5. truncate the local file to `server_statbuf.st_size`
6. Create a `fuse_file_info server_fi` and set `server_fi.flags` to `O_RDONLY` as we’re only reading contents of the file on the server
7. Call `open_rpc` to open the file on the server
8. Call `read_rpc` to read contents of the remote file into buf
9. write to local file and set local file timestamps
10. Make `release_rpc` call to close the remote file
11. Close local file
12. Make unlock rpc call to release the lock on the file

### Atomic Transfers

- Before performing actual upload/download, we first acquire the `rw_lock_t` of the remote file on the server by performing a `lock_rpc` call, and after all modification and transfers are down, we release the lock by calling `unlock_rpc`. This prevents other operations from intervening during the file transfer.

### Mutual Exclusion on the client side

- Only one writer can gain access to a remote file
- When server receives an open rpc call, and if the file doesn’t exist in the `file_mode_mapping`, if the mode is `O_RDONLY`, it wouldn’t affect the mode recorded in the mapping; otherwise, if the client attemps to write to the file, it fails if the file is already in write mode, protecting the file from overwriting. If the file is in read mode, we safely change its mode to write in the mapping to prevent future overwriting.

### Mutual Exclusion On the server side

- Achieved by using pthread mutexes `map_mutex` and `lock_mutex` to protect the `file_mode_mapping` and `file_lock_mapping` to ensure only one thread is accessing and modifying the mode or the lock of the file

### Steps to perform freshness checks to test Cache Invalidation

1. Get current time using time(0), set T = time(0)
2. Get last validation Tc by searching in the cache map in userdata
3.  If T – Tc < cache_interval, the entry is still fresh
4. Otherwise, call `getattr_rpc` to fetch latest server-side file stats and compare with local file stats
    1. If last modification time is the same, update Tc
    2. Otherwise, the cache has expired, and will need to perform a download action

## 2. All functions of the Project have been implemented

## 3. Error Codes Returned

- `-EACCES`

Returned by the server's `watdfs_open` when attempting to open a file for writing that is already open in write mode

- `-EMFILE`

Returned by the client if attempting to open a file that is already opened

## 4. Testing the Project

1. General Testing to make sure all functions are working as intended (1 client)

```cpp
- mknod(file) // file: /tmp/$USER/mount/myfile.txt
- fd = Open(file, os.O_RDWR)
- utime(file, time.time(), time.time())
- pwrite(file, “hahaha”.encode(), 0)
- pread(Fd, 5, 0)
- truncate(file, 2)
- fsync(fd)
- close(fd)
```

1. Testing file creation and closing (1 client)

```cpp
- fd = os.open(file, os.O_WRONLY | os.O_CREAT)
- Os.close(Fd)
# sets mode=O_RDONLY during watdfs_release
- fd = os.open(file, os.O_RDONLY) 
# should successfully open the file since previous mode is O_RDONLY
```

1. Testing for `–EACCES` error (2 clients)

```cpp
- Client 1: os.mknod(file)
- Client 1: fd = os.open(file, os.O_WRONLY)
- Client 2: fd = os.open(file, os.O_WRONLY)
# should fail with retcode –EACCES because it attemps to open a file with 
# write mode while the file is already in write mode
```

1. Testing for atomicity
- Have one file myfile.txt in server directory with content “abc”
- Create two threads, one continously calls open and write on mount1/myfile.txt with content interchanging between “abc” and “cba”. The other thread continously calles open with read mode and read from the "mount2/myfile.txt”
- The content read should be either “abc” or “cba” for the sake of atomicity
