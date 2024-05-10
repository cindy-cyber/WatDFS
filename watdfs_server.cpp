//
// Starter code for CS 454/654
// You SHOULD change this file
//

#include "rpc.h"
#include "debug.h"
#include "rw_lock.h"
INIT_LOG

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <fuse.h>
#include <unordered_map>
#include <string>
#include <cassert>

// Global state server_persist_dir.
char *server_persist_dir = nullptr;

// Important: the server needs to handle multiple concurrent client requests.
// You have to be careful in handling global variables, especially for updating them.
// Hint: use locks before you update any global variable.

enum file_mode { RD_MODE, WT_MODE };

std::unordered_map<std::string, rw_lock_t*> file_lock_mapping;
std::unordered_map<std::string, enum file_mode > file_mode_mapping;
pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;

// We need to operate on the path relative to the server_persist_dir.
// This function returns a path that appends the given short path to the
// server_persist_dir. The character array is allocated on the heap, therefore
// it should be freed after use.
// Tip: update this function to return a unique_ptr for automatic memory management.
char *get_full_path(char *short_path) {
    int short_path_len = strlen(short_path);
    int dir_len = strlen(server_persist_dir);
    int full_len = dir_len + short_path_len + 1;

    char *full_path = (char *)malloc(full_len);

    // First fill in the directory.
    strcpy(full_path, server_persist_dir);
    // Then append the path.
    strcat(full_path, short_path);
    DLOG("Full path: %s\n", full_path);

    return full_path;
}

// The server implementation of getattr.
int watdfs_getattr(int *argTypes, void **args) {
    // Get the arguments.
    // The first argument is the path relative to the mountpoint.
    char *short_path = (char *)args[0];
    // The second argument is the stat structure, which should be filled in
    // by this function.
    struct stat *statbuf = (struct stat *)args[1];
    // The third argument is the return code, which should be set be 0 or -errno.
    int *ret = (int *)args[2];

    // Get the local file name, so we call our helper function which appends
    // the server_persist_dir to the given path.
    char *full_path = get_full_path(short_path);

    // Initially we set the return code to be 0.
    *ret = 0;

    // TODO: Make the stat system call, which is the corresponding system call needed
    // to support getattr. You should use the statbuf as an argument to the stat system call.

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;
    sys_ret = stat(full_path, statbuf);

    if (sys_ret < 0) {
        // If there is an error on the system call, then the return code should
        // be -errno.
        *ret = -errno;
    }
    DLOG("ret %d", *ret);

    // Clean up the full path, it was allocated on the heap.
    free(full_path);

    //DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

// The server implementation of mknod.
int watdfs_mknod(int *argTypes, void **args) {
    // Get the arguments.
    char *short_path = (char *)args[0];

    // The second argument is the mode of the file
    mode_t *mode = (mode_t *)args[1];

    // The third argument is dev
    dev_t *dev = (dev_t *)args[2];

    // The fourth argument is return code
    int *ret = (int *)args[3];

    
    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;
    sys_ret = mknod(full_path, *mode, *dev);
    DLOG("mode: %d", *mode);
    DLOG("mode: %ld", *dev);
    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys mknod failed");
    } else {
      *ret = sys_ret;
      DLOG("sys mknod succeed");
    }

    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

int watdfs_open(int *argTypes, void **args) {
    // Get the arguments.
    char *short_path = (char *)args[0];

    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];

    int *ret = (int *)args[2];

    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    std::string relative_path(short_path);
    int mode = fi->flags & O_ACCMODE;

    int sys_ret = 0;
    pthread_mutex_lock(&map_mutex);

    if (file_mode_mapping.find(relative_path) != file_mode_mapping.end()) {      // file metadata exists
        if (mode != O_RDONLY) {     // attempt to open with WRITE mode
            if (file_mode_mapping[relative_path] != RD_MODE) {
                DLOG("return -EACCES, %d", -EACCES);
                *ret = -EACCES;
                goto end;
            } else {
                DLOG("set map mode to WT_MODE");
                file_mode_mapping[relative_path] = WT_MODE;
            }
        }
    } else {    // initialize lock for this file

        if (mode != O_RDONLY) {
            DLOG("new file, set WT mode");
            file_mode_mapping[relative_path] = WT_MODE;
        } else {
            DLOG("new file, set RD mode");
            file_mode_mapping[relative_path] = RD_MODE;
        }
    }
    pthread_mutex_unlock(&map_mutex);

    sys_ret = open(full_path, fi->flags);

    if (sys_ret < 0) {
      *ret = -errno;
    } else {
      fi->fh = sys_ret;
      *ret= 0;
    }

end:
    free(full_path);
    DLOG("Returning code: %d", *ret);
    return 0;
}

int watdfs_release(int *argTypes, void **args) {
    // Get the arguments.
    
    char *short_path = (char *)args[0];

    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];

    int *ret = (int *)args[2];

    char *full_path = get_full_path(short_path);

    *ret = 0;

    int my_mode = fi->flags & O_ACCMODE;

    pthread_mutex_lock(&map_mutex);
    auto file = file_mode_mapping.find(std::string(short_path));
    assert(file != file_mode_mapping.end());
    if (file != file_mode_mapping.end()) {
        if (my_mode != O_RDONLY) {
            file_mode_mapping[std::string(short_path)] = RD_MODE;
        }
    }
    pthread_mutex_unlock(&map_mutex);

    int sys_ret = 0;
    sys_ret = close(fi->fh);

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys close failed");
    } else {
      *ret = sys_ret;
      DLOG("sys close succeed");
    }

    
    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

int watdfs_read(int *argTypes, void **args) {
    // Get the arguments.

    char *short_path = (char *)args[0];

    // buffer that stores data
    char *buf = (char *)args[1];

    // how many bytes to read
    size_t *size = (size_t *)args[2];

    // start from offset
    off_t *offset = (off_t *)args[3];

    struct fuse_file_info *fi = (struct fuse_file_info *)args[4];

    int *ret = (int *)args[5];

    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;
    
    sys_ret = pread(fi->fh, buf, *size, *offset);

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys read failed");
    } else {
      *ret = sys_ret;
      DLOG("sys read succeed");
    }

    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return *ret;
}

int watdfs_write(int *argTypes, void **args) {
    // Get the arguments.

    char *short_path = (char *)args[0];
    const void *buf = args[1];
    size_t *size = (size_t *)args[2];
    off_t *offset = (off_t *)args[3];
    struct fuse_file_info *fi = (struct fuse_file_info *)args[4];
    int *ret = (int *)args[5];

    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;
    DLOG("size: %ld, offset: %ld", *size, *offset);
    DLOG("buf %s", (char *)buf);
    if (*size != 0) {
        sys_ret = pwrite(fi->fh, buf, *size, *offset);
    }

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys write failed");
    } else {
      *ret = sys_ret;
      DLOG("sys write succeed");
    }

    free(full_path);
    DLOG("Returning code: %d", *ret);

    return *ret;
}

int watdfs_truncate(int *argTypes, void **args) {
    // Get the arguments.
    
    char *short_path = (char *)args[0];

    // The second argument is new size
    off_t *size = (off_t *)args[1];

    int *ret = (int *)args[2];

    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;
    sys_ret = truncate(full_path, *size);

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys truncate failed");
    } else {
      *ret = sys_ret;
      DLOG("sys truncate succeed");
    }

    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

int watdfs_fsync(int *argTypes, void **args) {
    // Get the arguments.
    
    char *short_path = (char *)args[0];

    struct fuse_file_info *fi = (struct fuse_file_info *)args[1];

    int *ret = (int*) args[2];

    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;

    sys_ret = fsync(fi->fh);

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys fsync failed");
    } else {
      *ret = sys_ret;
      DLOG("sys fsync succeed");
    }

    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

int watdfs_utimensat(int *argTypes, void **args) {
    // Get the arguments.
    
    char *short_path = (char *)args[0];

    // times
    struct timespec *ts = (struct timespec *)args[1];

    int *ret = (int*)args[2];

    
    char *full_path = get_full_path(short_path);

    // Initially we set set the return code to be 0.
    *ret = 0;

    // Let sys_ret be the return code from the stat system call.
    int sys_ret = 0;

    sys_ret = utimensat(0, full_path, ts, 0);

    if (sys_ret < 0) {
      *ret = -errno;
      DLOG("sys utimens failed");
    } else {
      *ret = sys_ret;
      DLOG("sys utimens succeed");
    }

    
    free(full_path);
    DLOG("Returning code: %d", *ret);
    // The RPC call succeeded, so return 0.
    return 0;
}

int watdfs_lock(int *argTypes, void **args) {
    char *relative_path = (char *)args[0];

    rw_lock_mode_t mode = *((rw_lock_mode_t *)args[1]);

    int *ret = (int *)args[2];

    *ret = 0;

    // lock file lock
    DLOG("reached ehre in lock");
    pthread_mutex_lock(&lock_mutex);
    DLOG("acquired lock_mutex in lock");

    auto file = file_lock_mapping.find(std::string(relative_path));
    if (file == file_lock_mapping.end()) {
        rw_lock_t* lock = (rw_lock_t*)malloc(sizeof(rw_lock_t));
        file_lock_mapping[std::string(relative_path)] = lock;
        rw_lock_init(file_lock_mapping[std::string(relative_path)]);
    }

    pthread_mutex_unlock(&lock_mutex);
    int sys_ret = rw_lock_lock(file_lock_mapping[std::string(relative_path)], mode);
    DLOG("acquired file lock");
    DLOG("reahed unlock map lock in lock");
    if (sys_ret < 0) {
        *ret = -errno;
    }

    return 0;
}

int watdfs_unlock(int *argTypes, void **args) {
    char *relative_path = (char *)args[0];

    rw_lock_mode_t mode = *((rw_lock_mode_t *)args[1]);

    int *ret = (int *)args[2];

    *ret = 0;

    // unlock file lock
    DLOG("reached here in unlock;");
    pthread_mutex_lock(&lock_mutex);
    
    DLOG("reached here past the lock_mutex");
    auto file = file_lock_mapping.find(std::string(relative_path));
    assert(file != file_lock_mapping.end());
    pthread_mutex_unlock(&lock_mutex);
    int sys_ret = rw_lock_unlock(file_lock_mapping[std::string(relative_path)], mode);
    DLOG("released file lock");
    
    DLOG("reahed unlock map lock in unlock");
    if (sys_ret < 0) {
        *ret = -errno;
    }

    return 0;
}

// The main function of the server.
int main(int argc, char *argv[]) {
    // argv[1] should contain the directory where you should store data on the
    // server. If it is not present it is an error, that we cannot recover from.
    if (argc != 2) {
        // In general, you shouldn't print to stderr or stdout, but it may be
        // helpful here for debugging. Important: Make sure you turn off logging
        // prior to submission!
        // See watdfs_client.cpp for more details
        // # ifdef PRINT_ERR
        // std::cerr << "Usage:" << argv[0] << " server_persist_dir";
        // #endif
        return -1;
    }
    // Store the directory in a global variable.
    server_persist_dir = argv[1];

    // TODO: Initialize the rpc library by calling `rpcServerInit`.
    // Important: `rpcServerInit` prints the 'export SERVER_ADDRESS' and
    // 'export SERVER_PORT' lines. Make sure you *do not* print anything
    // to *stdout* before calling `rpcServerInit`.
    //DLOG("Initializing server...");
    int init_retcode = rpcServerInit();
    
    int ret = 0;
    // TODO: If there is an error with `rpcServerInit`, it maybe useful to have
    // debug-printing here, and then you should return.
    if (init_retcode < 0) {
        DLOG("Initialize server failed.");
        return init_retcode;
    } 
    DLOG("Initialize server succeeded.");

    // TODO: Register your functions with the RPC library.
    // Note: The braces are used to limit the scope of `argTypes`, so that you can
    // reuse the variable for multiple registrations. Another way could be to
    // remove the braces and use `argTypes0`, `argTypes1`, etc.
    {
        // There are 3 args for the function (see watdfs_client.cpp for more
        // detail).
        int argTypes[4];
        // First is the path.
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        // The second argument is the statbuf.
        argTypes[1] =
            (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        // The third argument is the retcode.
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        // Finally we fill in the null terminator.
        argTypes[3] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *)"getattr", argTypes, watdfs_getattr);
        if (ret < 0) {
            // It may be useful to have debug-printing here.
            return ret;
        }
    }

    // Register mknod
    {
        // There are 4 args for the function.
        int argTypes[5];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] =  (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[4] = 0;

        ret = rpcRegister((char *) "mknod", argTypes, watdfs_mknod);
        if (ret < 0) {
            DLOG("Register mknod fail");
	        return ret;
        }
        DLOG("Register mknod succeed");
    }

    // Register open
    {
        // There are 3 args for the function.
        int argTypes[4];
        
        argTypes[0] = 
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u ;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *) "open", argTypes, watdfs_open);
        if (ret < 0) {
            DLOG("Register open fail");
	        return ret;
        }
        DLOG("Register open succeed");
    }

    // Register release
    {
        // There are 3 args for the function.
        int argTypes[4];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *) "release", argTypes, watdfs_release);
        if (ret < 0) {
            DLOG("Register release fail");
	        return ret;
        }
        DLOG("Register release succeed");
    }

    // Register read
    {
        // There are 6 args for the function.
        int argTypes[7];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[4] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[6] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *) "read", argTypes, watdfs_read);
        if (ret < 0) {
            DLOG("Register read fail");
	        return ret;
        }
        DLOG("Register read succeed");
    }

    // Register write
    {
        // There are 6 args for the function.
        int argTypes[7];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[4] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[6] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *) "write", argTypes, watdfs_write);
        if (ret < 0) {
            DLOG("Register write fail");
	        return ret;
        }
        DLOG("Register write succeed");
    }

    // Register truncate
    {
        // There are 3 args for the function.
        int argTypes[4];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        // We need to register the function with the types and the name.
        ret = rpcRegister((char *) "truncate", argTypes, watdfs_truncate);
        if (ret < 0) {
            DLOG("Register truncate fail");
	        return ret;
        }
        DLOG("Register truncate succeed");
    }

    // Register fsync
    {
        // There are 3 args for the function.
        int argTypes[4];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *) "fsync", argTypes, watdfs_fsync);
        if (ret < 0) {
            DLOG("Register fsync fail");
	          return ret;
        }
        DLOG("Register fsync succeed");
    }

    // Register utimensat
    {
        // There are 3 args for the function.
        int argTypes[4];
        
        argTypes[0] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] =
            (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *) "utimensat", argTypes, watdfs_utimensat);
        if (ret < 0) {
            DLOG("Register utimensat fail");
	        return ret;
        }
        DLOG("Register utimensat succeed");
    }

    // Register lock
    {
        int argTypes[4];

        argTypes[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"lock", argTypes, watdfs_lock);
        if (ret < 0) {
            return ret;
        }
    }

    // Register unlock
    {
        int argTypes[4];

        argTypes[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 1u;
        argTypes[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
        argTypes[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        argTypes[3] = 0;

        ret = rpcRegister((char *)"unlock", argTypes, watdfs_unlock);
        if (ret < 0) {
            return ret;
        }
    }

    ret = rpcExecute();

    if (ret < 0) {
        DLOG("rpcExecute failed");
        return ret;
    } 

    DLOG("rpcExecute succeeded");
    return ret;
}
