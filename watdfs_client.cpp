//
// Starter code for CS 454/654
// You SHOULD change this file
//
#include <algorithm>
#include <unordered_map>
#include <string>
#include <cassert>
#include "watdfs_client.h"
#include "debug.h"
#include "rw_lock.h"
INIT_LOG

#include "rpc.h"


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


void *watdfs_cli_init(struct fuse_conn_info *conn, const char *path_to_cache,
                      time_t cache_interval, int *retcode) { // ne
    int init_retcode = rpcClientInit();
    if (init_retcode < 0) {
        DLOG("rpcClientInt failed!");
    } else {
        DLOG("rpcClientInt succeeded.");
    }

    // save `path_to_cache` and `cache_interval`.
    struct client_meta *userdata = new struct client_meta;
    userdata->path_to_cache = new char[strlen(path_to_cache) + 1];
    strcpy(userdata->path_to_cache, path_to_cache);
    userdata->cache_interval = cache_interval;

    // set retcode
    *retcode = init_retcode;

    // return pointer to global state data.
    return userdata;
}

void watdfs_cli_destroy(void *userdata) {       // Done
    // TODO: clean up your userdata state.
    struct client_meta *client = (client_meta *)userdata;
    delete client->path_to_cache;
    delete client;

    // TODO: tear n the RPC library by calling `rpcClientDestroy`.
    int destroy_retcode = rpcClientDestroy();
    if (destroy_retcode < 0) {
        DLOG("rpcClientDestroy failed!");
    } else {
        DLOG("rpcClientDestroy succeeded.");
    }
    userdata = nullptr;
}

int getattr_rpc(void *userdata, const char *path, struct stat *statbuf) {
    // SET UP THE RPC CALL
    DLOG("getattr_rpc called for '%s'", path);
    
    // getattr has 3 arguments.
    int ARG_COUNT = 3;

    // Allocate space for the output arguments.
    void **args = new void*[ARG_COUNT];

    // Allocate the space for arg types, and one extra space for the null
    // array element.
    int arg_types[ARG_COUNT + 1];

    // The path has string length (strlen) + 1 (for the null character).
    int pathlen = strlen(path) + 1;

    // Fill in the arguments
    // The first argument is the path, it is an input only argument, and a char
    // array. The length of the array is the length of the path.
    arg_types[0] =
        (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    // For arrays the argument is the array pointer, not a pointer to a pointer.
    args[0] = (void *)path;

    // The second argument is the stat structure. This argument is an output
    // only argument, and we treat it as a char array. The length of the array
    // is the size of the stat structure, which we can determine with sizeof.
    arg_types[1] = (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
                   (uint) sizeof(struct stat); // statbuf
    args[1] = (void *)statbuf;

    // The third argument is the return code, an output only argument, which is
    // an integer.
    // TODO: fill in this argument type.
    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);

    // The return code is not an array, so we need to hand args[2] an int*.
    // The int* could be the address of an integer located on the stack, or use
    // a heap allocated integer, in which case it should be freed.
    // TODO: Fill in the argument
    int retcode = 0;
    args[2] = (void *) &retcode;

    // Finally, the last position of the arg types is 0. There is no
    // corresponding arg.
    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"getattr", arg_types, args);

    // HANDLE THE RETURN
    // The integer value watdfs_cli_getattr will return.
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("getattr rpc failed with error '%d'", rpc_ret);
        // Something went wrong with the rpcCall, return a sensible return
        // value. In this case lets return, -EINVAL
        fxn_ret = -EINVAL;
    } else {
        // Our RPC call succeeded. However, it's possible that the return code
        // from the server is not 0, that is it may be -errno. Therefore, we
        // should set our function return value to the retcode from the server.

        // TODO: set the function return value to the return code from the server.
        fxn_ret = retcode;
    }

    if (fxn_ret < 0) {
        // If the return code of watdfs_cli_getattr is negative (an error), then 
        // we need to make sure that the stat structure is filled with 0s. Otherwise,
        // FUSE will be confused by the contradicting return values.
        memset(statbuf, 0, sizeof(struct stat));
    }

    // Clean up the memory we have allocated.
    delete []args;

    // Finally return the value we got from the server.
    return fxn_ret;
}

// CREATE, OPEN AND CLOSE
int mknod_rpc(void *userdata, const char *path, mode_t mode, dev_t dev) {
    // Called to create a file.
    // SET UP THE RPC CALL
    DLOG("watdfs_cli_mknod called for '%s'", path);
    
    // getattr has 4 arguments.
    int ARG_COUNT = 4;

    // Allocate space for the output arguments.
    void **args = new void*[ARG_COUNT];

    // Allocate the space for arg types, and one extra space for the null
    // array element.
    int arg_types[ARG_COUNT + 1];

    // The path has string length (strlen) + 1 (for the null character).
    int pathlen = strlen(path) + 1;

    // Fill in the arguments
    // The first argument is the path, it is an input only argument, and a char
    // array. The length of the array is the length of the path.
    arg_types[0] =
        (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    // For arrays the argument is the array pointer, not a pointer to a pointer.
    args[0] = (void *)path;

    // The second argument is the mode. This argument is an input
    // only argument, and we treat it as an int.
    arg_types[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
    args[1] = (void *)(&mode);

    // The second argument is the dev. This argument is an input
    // only argument, and we treat it as a long.
    arg_types[2] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
    args[2] = (void *)(&dev);

    // The return code
    arg_types[3] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[3] = (void *) &retcode;

    arg_types[4] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"mknod", arg_types, args);

    // HANDLE THE RETURN
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("mknod rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    // Clean up the memory we have allocated.
    delete []args;

    // Finally return the value we got from the server.
    return fxn_ret;
}

int open_rpc(void *userdata, const char *path, struct fuse_file_info *fi) {
    // Called during open.
    // You should fill in fi->fh.

    // SET UP THE RPC CALL
    DLOG("open_rpc called for '%s'", path);
    
    // open has 3 arguments.
    int ARG_COUNT = 3;

    // Allocate space for the output arguments.
    void **args = new void*[ARG_COUNT];

    // Allocate the space for arg types, and one extra space for the null
    // array element.
    int arg_types[ARG_COUNT + 1];

    // The path has string length (strlen) + 1 (for the null character).
    int pathlen = strlen(path) + 1;

    // Fill in the arguments
    arg_types[0] =
        (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    // For arrays the argument is the array pointer, not a pointer to a pointer.
    args[0] = (void *)path;

    // The second argument is the fi structure. This argument is an input/output
    // argument, and we treat it as a char array. The length of the array
    // is the size of the fi structure, which we can determine with sizeof.
    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
        (uint) sizeof(struct fuse_file_info); // fi
    args[1] = (void *)fi;

    // The return code
    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = (void *) &retcode;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"open", arg_types, args);

    // HANDLE THE RETURN
    
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("open rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    // Clean up the memory we have allocated.
    delete []args;

    // Finally return the value we got from the server.
    return fxn_ret;
}

int release_rpc(void *userdata, const char *path, struct fuse_file_info *fi) {
    // Called during close, but possibly asynchronously.
    DLOG("release_rpc called for '%s'", path);
    
    // open has 3 arguments.
    int ARG_COUNT = 3;

    // Allocate space for the output arguments.
    void **args = new void*[ARG_COUNT];

    // Allocate the space for arg types, and one extra space for the null
    // array element.
    int arg_types[ARG_COUNT + 1];

    // The path has string length (strlen) + 1 (for the null character).
    int pathlen = strlen(path) + 1;

    // Fill in the arguments
    // The first argument is the path, it is an input only argument, and a char
    // array. The length of the array is the length of the path.
    arg_types[0] =
        (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    // For arrays the argument is the array pointer, not a pointer to a pointer.
    args[0] = (void *)path;

    // The second argument is the fi structure. This argument is an input only
    // argument, and we treat it as a char array. The length of the array
    // is the size of the fi structure, which we can determine with sizeof.
    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | 
        (uint) sizeof(struct fuse_file_info); // fi
    args[1] = (void *)fi;

    // The return code
    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = (void *) &retcode;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"release", arg_types, args);

    // HANDLE THE RETURN
    
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("release rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    // Clean up the memory we have allocated.
    delete []args;

    // Finally return the value we got from the server.
    return fxn_ret;
}

// READ AND WRITE DATA
int read_rpc(void *userdata, const char *path, char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    // Read size amount of data at offset of file into buf.
    // Remember that size may be greater than the maximum array size of the RPC
    // library.
    size_t remaining_size = size;           // remaining size the buf can contain
    int arr_size = 0;
    off_t curr_offset = offset;
    int retcode = 0;
    int read = 0;

    do {
        int ARG_COUNT = 6;
        void **args = new void*[ARG_COUNT];
        int arg_types[ARG_COUNT + 1];

        int pathlen = strlen(path) + 1;
        if (remaining_size >= MAX_ARRAY_LEN) {
            arr_size = MAX_ARRAY_LEN;
        } else {
            arr_size = remaining_size;
        }
        retcode = 0;

        arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
        args[0] = (void *)path;

        arg_types[1] = (1u << ARG_OUTPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) arr_size;
        args[1] = (void *)buf;

        arg_types[2] =  (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[2] = (void *)&arr_size;

        arg_types[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[3] = (void *)&curr_offset;

        arg_types[4] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
            (uint)sizeof(struct fuse_file_info);
        args[4] = (void *)fi;

        arg_types[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        args[5] = (void *) &retcode;

        arg_types[6] = 0;

        // MAKE THE RPC CALL
        int rpc_ret = rpcCall((char *)"read", arg_types, args);

        delete []args;

        // HANDLE THE RETURN
        int fxn_ret = 0;
        if (rpc_ret < 0) {
            DLOG("read rpc failed with error '%d'", rpc_ret);
            fxn_ret = -EINVAL;
            return fxn_ret;
        }

        // error return -errno
        if (retcode < 0) {
            return retcode;
        }
    
        // incorrect number of bytes read, return bytes actually read
        if (retcode < arr_size) {
            return retcode + read;
        }

        // reset remaining_size, read, curr_offset, buf ptr
        remaining_size -= arr_size;
        read += retcode;
        curr_offset += retcode;
        buf += retcode;
    } while (remaining_size > 0 && retcode == MAX_ARRAY_LEN);
    
    // success
    return read;
}

int write_rpc(void *userdata, const char *path, const char *buf,
                     size_t size, off_t offset, struct fuse_file_info *fi) {
    // Write size amount of data at offset of file from buf.
    // Remember that size may be greater than the maximum array size of the RPC
    // library.
    size_t remaining_size = size;
    // size_t maxRpcSize = MAX_ARRAY_LEN;
    int arr_size = 0;
    off_t curr_offset = offset;
    int retcode = 0;
    int written = 0;

    do {
        int ARG_COUNT = 6;
        void **args = new void*[ARG_COUNT];
        int arg_types[ARG_COUNT + 1];

        int pathlen = strlen(path) + 1;
        if (remaining_size >= MAX_ARRAY_LEN) {
            arr_size = MAX_ARRAY_LEN;
        } else {
            arr_size = remaining_size;
        }
        retcode = 0;

        arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
        args[0] = (void *)path;

        arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) arr_size;
        args[1] = (void *)buf;

        arg_types[2] =  (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[2] = (void *)&arr_size;

        arg_types[3] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
        args[3] = (void *)&curr_offset;

        arg_types[4] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) |
            (uint)sizeof(struct fuse_file_info);
        args[4] = (void *)fi;

        arg_types[5] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
        args[5] = (void *)&retcode;

        arg_types[6] = 0;

        // MAKE THE RPC CALL
        int rpc_ret = rpcCall((char *)"write", arg_types, args);

        delete []args;
        
        // HANDLE THE RETURN
        int fxn_ret = 0;
        if (rpc_ret < 0) {
            DLOG("write rpc failed with error '%d'", rpc_ret);
            fxn_ret = -EINVAL;
            return fxn_ret;
        }

        // error return -errno
        if (retcode < 0) {
            return retcode;
        }
        
        // incorrect number of bytes written, return bytes actually written
        if (retcode != arr_size) {
            return retcode + written;
        }

        // reset remaining_size, written, curr_offset, buf ptr
        remaining_size -= arr_size;
        written += retcode;
        curr_offset += retcode;
        buf += retcode;


    } while (remaining_size > 0 && retcode == MAX_ARRAY_LEN);
    
    // success
    return written;
}

int truncate_rpc(void *userdata, const char *path, off_t newsize) {
    // Change the file size to newsize.
    int ARG_COUNT = 3;
    void **args = new void*[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    int retcode = 0;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (ARG_LONG << 16u);
    args[1] = (void *)(&newsize);

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    args[2] = (void *) &retcode;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"truncate", arg_types, args);

    // HANDLE THE RETURN
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("truncate rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete []args;
    return fxn_ret;
}

int fsync_rpc(void *userdata, const char *path,
                     struct fuse_file_info *fi) {
    // Force a flush of file data.
    int ARG_COUNT = 3;
    void **args = new void*[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    int retcode = 0;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) sizeof(struct fuse_file_info);
    args[1] = (void *)fi;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    args[2] = (void *) &retcode;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"fsync", arg_types, args);

    // HANDLE THE RETURN
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("fsync rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete []args;
    return fxn_ret;
}

// CHANGE METADATA
int utimensat_rpc(void *userdata, const char *path,
                       const struct timespec ts[2]) {
    // Change file access and modification times.
    int ARG_COUNT = 3;
    void **args = new void*[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];

    int pathlen = strlen(path) + 1;
    int retcode = 0;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    args[0] = (void *)path;

    arg_types[1] = (1u << ARG_INPUT) |(1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) sizeof(struct timespec) * 2;
    args[1] = (void *)ts;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    args[2] = (void *) &retcode;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"utimensat", arg_types, args);

    // HANDLE THE RETURN
    int fxn_ret = 0;
    if (rpc_ret < 0) {
        DLOG("utimensat rpc failed with error '%d'", rpc_ret);
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete []args;
    return fxn_ret;
}



/* Lock rpcs */
int lock_rpc(const char *path, rw_lock_mode_t mode) {

    int ARG_COUNT = 3;
    void **args = new void*[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];
    int pathlen = strlen(path) + 1;

    arg_types[0] = (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | pathlen;
    args[0] = (void *) path;

    arg_types[1] = (1u << ARG_INPUT) |  (ARG_INT << 16u) ;
    args[1] = (void *) &mode;

    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u) ;

    int ret_code;
    args[2] = (void *) &ret_code;

    arg_types[3] = 0;

    // MAKE THE RPC CALL
    int rpc_ret = rpcCall((char *)"lock", arg_types, args);

    // HANDLE THE RETURN
    int fxn_ret = 0;

    if (rpc_ret < 0) {
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = ret_code;
    }

    delete []args;
    return fxn_ret;
}

int unlock_rpc(const char *path, rw_lock_mode_t mode){

    int ARG_COUNT = 3;
    void **args = new void*[ARG_COUNT];
    int arg_types[ARG_COUNT + 1];
    int pathlen = strlen(path) + 1;

    arg_types[0] =
        (1u << ARG_INPUT) | (1u << ARG_ARRAY) | (ARG_CHAR << 16u) | (uint) pathlen;
    args[0] = (void *)path;


    arg_types[1] = (1u << ARG_INPUT) | (ARG_INT << 16u);
    args[1] = (void *) &mode;


    arg_types[2] = (1u << ARG_OUTPUT) | (ARG_INT << 16u);
    int retcode = 0;
    args[2] = (int *) &retcode;
    
    arg_types[3] = 0;

    int rpc_ret = rpcCall((char *)"unlock", arg_types, args);

    int fxn_ret = 0;
    if (rpc_ret < 0) {
        fxn_ret = -EINVAL;
    } else {
        fxn_ret = retcode;
    }

    delete []args;

    return fxn_ret;
}


// helper functions
bool is_file_open(void *userdata, const char *local_full_path) {
    struct client_meta *client_data = (client_meta *)userdata;
    DLOG("So far so good");
    for (const auto& pair : client_data->cache) {
        DLOG("KEY, %s", pair.first.c_str()); // pair.first is the key
    }
    const auto &it = (client_data->cache).find(std::string(local_full_path));
    if (it != (client_data->cache).end()) {
        // return (it->second).fh != -1;

        DLOG("FOUND KEY, %s", (it->first).c_str());
        return true;
    }
    return false;
}

char *get_full_path(void *userdata, const char* relative_path) {
    // DLOG("Start fet full path");
    struct client_meta *client_data= (client_meta *)userdata;
    // DLOG("got client data");
    const char *path_to_cache = client_data->path_to_cache;
    // DLOG("got path to cache");

    int full_path_len = strlen(path_to_cache) + strlen(relative_path) + 1;
    // DLOG("got full path length");

    char *full_path = new char[full_path_len];
    strcpy(full_path, path_to_cache); // store cache path to full_path
    // DLOG("stored cahce path to full path");
    strcat(full_path, relative_path); // append relative_path 
    // DLOG("stored relative path to full path");

    return full_path;
}

int get_file_flags(void *userdata, char *local_full_path) {
  int flags = -1;
  struct client_meta *client_data = (client_meta *)userdata;
  auto it = (client_data->cache).find(std::string(local_full_path));
  if (it != (client_data->cache).end()) {
      flags = (it->second)->flags & O_ACCMODE;
  }

  return flags;
}


int get_fh(void *userdata, char *local_full_path) {
  int fh = -1;
  struct client_meta *client_data = (client_meta *)userdata;
  auto it = (client_data->cache).find(std::string(local_full_path));
  if (it != (client_data->cache).end()) {
      fh = (it->second)->fh;
  }
  return fh;
}


/* update the cache's last validation time to current time*/
void update_tc(void *userdata, const char *relative_path) {
  struct client_meta *client_data = (client_meta *)userdata;

  // TODO: do we need to check if the file exists?
  auto it = (client_data->cache).find(std::string(get_full_path(userdata, relative_path)));
  if (it != (client_data->cache).end()) {
      (it->second)->tc = time(0);
  }
}

/* check if file can be served from the locally cached file copy 
*/
bool check_update_freshness_condition(void *userdata, const char *relative_path) {
    struct client_meta *client_data = (client_meta *)userdata;
    std::string local_full_path(get_full_path(userdata, relative_path));
    time_t t = time(0);
    time_t tc = ((client_data->cache).find(local_full_path)->second)->tc;

    if (t - tc < client_data->cache_interval) {
      return true;
    }

    /* first check fails, determine T_server by consulting the server */
    struct stat server_statbuf;
    struct stat client_statbuf;

    int ret = 0;
    ret = getattr_rpc(userdata, relative_path, &server_statbuf);
    if (ret < 0) DLOG("getattr server-side failed");
    ret = stat(local_full_path.c_str(), &client_statbuf);
    if (ret < 0) DLOG("stat client-side failed");

    if (client_statbuf.st_mtime == server_statbuf.st_mtime) {     // check last modification time
        update_tc(userdata, relative_path);            // Tc should be updated to the current time
        return true;
    }
    return false;
}

// Upload/Downloadad model

/* Transfer file from servert to client 
 *
 * truncate the file at the client, get file attributes from the server,
 * read the file from the server, write the file to the client, and
 * then update the file metadata at the client
 */
int download_to_client(void *userdata, const char *path) {
    DLOG("Download starts");
    int rpc_ret = 0;
    int fxn_ret = 0;
    char *local_full_path = get_full_path(userdata, path);
    int client_fh;
    char *buf;

    struct stat server_statbuf;
    rpc_ret = lock_rpc(path, RW_READ_LOCK);
    if (rpc_ret < 0) {
        DLOG("failed lock");
        fxn_ret = rpc_ret;
        goto cleanup;
    }

    rpc_ret = getattr_rpc(userdata, path, &server_statbuf);
    if (rpc_ret < 0) {
        DLOG("File doesn't exist");
        fxn_ret = rpc_ret;
        goto unlock;
    }
    buf = new char[server_statbuf.st_size];   // TODO change it

    // file is already in local storage, just not opened (fh = -1)) or not even in cache yet; create the file if NOT exists
    client_fh = open(local_full_path, O_RDWR | O_CREAT, 0666);

    rpc_ret = truncate(local_full_path, server_statbuf.st_size);
    if (rpc_ret < 0) {
        DLOG("Failed truncate");
        fxn_ret = rpc_ret;
    }
  
    // proceed only if no error so far
    if (fxn_ret < 0) {
        // goto cleanup;
        goto close_cleanup;
        // goto unlock;
    }

    // read file from the server
    struct fuse_file_info server_fi;
    server_fi.flags = O_RDONLY;   // only read file to copy
    rpc_ret = open_rpc(userdata, path, &server_fi);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        DLOG("failed open rpc");
        // goto cleanup;
        // goto unlock;
        goto close_cleanup;
    } 

    /* no error so far, lock */
    // rpc_ret = lock_rpc(path, RW_READ_LOCK);
    // if (rpc_ret < 0) {
    //     DLOG("failed lock");
    //     fxn_ret = rpc_ret;
    //     goto cleanup;
    // }

    rpc_ret = read_rpc(userdata, path, buf, server_statbuf.st_size, 0, &server_fi);
    // assert(rpc_ret >= 0);
    if (rpc_ret < 0) {
        DLOG("read_rpc called");
        fxn_ret = rpc_ret;
        // goto unlock;
        // goto release_unlock;
        goto release;
    }

    // write file to the client
    rpc_ret = pwrite(client_fh, buf, server_statbuf.st_size, 0);
    if (rpc_ret < 0) {
        DLOG("write to buf failed");
        fxn_ret = rpc_ret;
        // goto unlock;
        // goto release_unlock;
        goto release;
    }

    // update client-side file metadata
    struct timespec newts[2];
    newts[0] = server_statbuf.st_mtim;
    newts[1] = server_statbuf.st_mtim;
    rpc_ret = utimensat(0, local_full_path, newts, 0);   // TODO check utimensat
    if (rpc_ret < 0) {
        DLOG("utimensat failed");
        fxn_ret = rpc_ret;
        // goto unlock;
        // goto release_unlock;
        goto release;
    }

    // release lock

release:
    DLOG("release_rpc called in downalod_to_client");
    rpc_ret = release_rpc(userdata, path, &server_fi);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        goto cleanup;
    }


close_cleanup:
    rpc_ret = close(client_fh);
    if (rpc_ret < 0) {
        DLOG("close file fail");  
    } 
    fxn_ret = rpc_ret;
    delete buf;

unlock:
    rpc_ret = unlock_rpc(path, RW_READ_LOCK);
    if (rpc_ret < 0) {
        DLOG("failed unlock");
        fxn_ret = rpc_ret;
        goto cleanup;
    }

cleanup:
    delete local_full_path;
    return fxn_ret;

}

// os.mknod -> cli_getattr -> cli_mknod -> cli_getattr
int upload_to_server(void *userdata, const char *path)
{
    DLOG("upload to server starts");
    int rpc_ret = 0;
    int fxn_ret = 0;
    char *local_full_path = get_full_path(userdata, path);
    struct stat client_statbuf;
    int client_fh;
    bool is_opened = false;

    // get attributes from both sides
    int sys_ret = stat(local_full_path, &client_statbuf);
    char *buf = new char[client_statbuf.st_size];
    if (sys_ret < 0) {
        fxn_ret = sys_ret;
        // goto cleanup;
        goto unlock;
    }

    // copy server stat
    struct stat server_statbuf;
    struct fuse_file_info server_fi;
    rpc_ret = getattr_rpc(userdata, path, &server_statbuf);
    if (rpc_ret < 0) {
        DLOG("File not exists");

        // make such file at server
        rpc_ret = mknod_rpc(userdata, path, client_statbuf.st_mode, client_statbuf.st_dev);
        if (rpc_ret < 0) {
            fxn_ret = rpc_ret;
            // goto cleanup;
            goto unlock;
        }
        // open with RW mode
        server_fi.flags = O_RDWR;
        rpc_ret = open_rpc(userdata, path, &server_fi);
        if (rpc_ret < 0) {
            fxn_ret = rpc_ret;
            // goto cleanup;
            goto unlock;
        }

    } else { // else file is opened at server-side
        struct client_meta *client = (client_meta *)userdata;
        server_fi.fh = (client->cache)[std::string(local_full_path)]->server_fh;
        server_fi.flags = (client->cache)[std::string(local_full_path)]->flags;
        is_opened = true;
    }

    /* lock */
    // rpc_ret = lock_rpc(path, RW_WRITE_LOCK);
    // if (rpc_ret < 0) {
    //     fxn_ret = rpc_ret;
    //     // goto close_cleanup; 
    //     goto cleanup;
    // }

    // open file at client side
    client_fh = open(local_full_path, O_RDONLY);
    if (client_fh < 0) {
        fxn_ret = -errno;
        // goto cleanup;
        // goto unlock;
        goto release;
    }

    // read file from the client
    rpc_ret = pread(client_fh, buf, client_statbuf.st_size, 0);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        // goto close_cleanup;
        goto close_cleanup;
    }

    //  /* lock */
    // rpc_ret = lock_rpc(path, RW_WRITE_LOCK);
    // if (rpc_ret < 0) {
    //     fxn_ret = rpc_ret;
    //     goto close_cleanup;
    // }

    // resize file at server side
    rpc_ret = truncate_rpc(userdata, path, client_statbuf.st_size);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        // goto unlock;
        goto close_cleanup;
    }

    // write file to the server
    rpc_ret = write_rpc(userdata, path, buf, client_statbuf.st_size, 0, &server_fi);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        // goto unlock;
        goto close_cleanup;
    }

    // load_date server-side metadata
    struct timespec newts[2];
    newts[0] = client_statbuf.st_mtim;
    newts[1] = client_statbuf.st_mtim;
    rpc_ret = utimensat_rpc(userdata, path, newts);
    if (rpc_ret < 0) {
        DLOG("utimensat failed");
        fxn_ret = rpc_ret;
        // goto unlock;
        goto close_cleanup;
    }


close_cleanup:

    rpc_ret = close(client_fh);
    DLOG("Close ret %d", rpc_ret);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        goto unlock;
    }

release:
    // release lock
    
    if (!is_opened) {
        DLOG("release_rpc called in upload_to_server");
        rpc_ret = release_rpc(userdata, path, &server_fi);
        if (rpc_ret < 0) {
            fxn_ret = rpc_ret;
            goto unlock;
        }
    }

unlock:

    rpc_ret = unlock_rpc(path, RW_WRITE_LOCK);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
    }

    delete buf;
    delete local_full_path;
    return fxn_ret;

}



// GET FILE ATTRIBUTES
int watdfs_cli_getattr(void *userdata, const char *path, struct stat *statbuf) {
    DLOG("watdfs_cli_getattr called for '%s'", path);

    int rpc_ret = 0;
    int fxn_ret = 0;
    // struct stat server_statbuf;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {    // file is open and in cache, 2 cases
        DLOG("File is open: %s", local_full_path);
        if (get_file_flags(userdata, local_full_path) == O_RDONLY && !check_update_freshness_condition(userdata, path)) {
            DLOG("open mode rdonly and needs refresh: %s", local_full_path);
            // first get server-side file stat to prepare for download
            // rpc_ret = getattr_rpc(userdata, path, &server_statbuf); // must succeed since file is opened
            // if (rpc_ret < 0) {
            //     DLOG("getattr_rpc failed for file '%s', file doesn't exist", path);
            //     fxn_ret = rpc_ret;
            //     goto error_cleanup;
            // }
            DLOG("cli_getattr file is open download");
            rpc_ret = download_to_client(userdata, path);
            if (rpc_ret < 0) {
                fxn_ret = rpc_ret;
                goto error_cleanup;
            } else {
                update_tc(userdata, path);
            }
            
        } // else in write mode, directly get stat

        rpc_ret = stat(local_full_path, statbuf);
        if (rpc_ret < 0) {
            fxn_ret = -EINVAL;
        }

    } else {  // file has not been opened
        DLOG("File is not opened: %s", local_full_path);
        // rpc_ret = getattr_rpc(userdata, path, &server_statbuf);
        // if (rpc_ret < 0) {
        //     DLOG("getattr_rpc failed for file '%s', file doesn't exist", path);
        //     fxn_ret = rpc_ret;
        // } else { 
        DLOG("cli_getattr file not open download");
        rpc_ret = download_to_client(userdata, path);
        if (rpc_ret < 0) {
            DLOG("Download failed for file '%s'", path);
            fxn_ret = rpc_ret;
        } else {
            // int client_fh = open(local_full_path, O_RDONLY);
            rpc_ret = stat(local_full_path, statbuf);
            // rpc_ret = close(client_fh);
            if (rpc_ret < 0) {
                fxn_ret = rpc_ret;
            }
        }
        // }
    }

    if (fxn_ret < 0) {
        memset(statbuf, 0, sizeof(struct stat));
    }

error_cleanup:

    delete local_full_path;
    return fxn_ret;

}


int watdfs_cli_mknod(void *userdata, const char *path, mode_t mode, dev_t dev) {
    DLOG("watdfs_cli_mknod started");

    int rpc_ret = 0;
    int fxn_ret = 0;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        if (get_file_flags(userdata, local_full_path) == O_RDONLY) {
            DLOG("mknod not allowed for file open in read only mode");
            fxn_ret = -EMFILE;
        } else {
            rpc_ret = mknod(local_full_path, mode, dev); 
            if (rpc_ret < 0) {
                DLOG("mknod operation failed: file already exists on client");
                fxn_ret = -errno;
            } else { // perform freshness checks at the end of writes
                if (!check_update_freshness_condition(userdata, path)) {
                    lock_rpc(path, RW_WRITE_LOCK);
                    rpc_ret = upload_to_server(userdata, path);
                    // unlock_rpc(path, RW_WRITE_LOCK);
                    if (rpc_ret < 0) {
                        fxn_ret = rpc_ret;
                    } else {
                        update_tc(userdata, path);
                    }
                    // release_rpc(userdata, path, &server_fi);
                }
            }
        }

    } else {
        rpc_ret = mknod(local_full_path, mode, dev); 
        if (rpc_ret < 0) {
            DLOG("mknod operation failed: file already exists on client");
            fxn_ret = -errno;
        } else {
            lock_rpc(path, RW_WRITE_LOCK);
            rpc_ret = upload_to_server(userdata, path);
            // unlock_rpc(path, RW_WRITE_LOCK);
            if (rpc_ret < 0) {
                fxn_ret = rpc_ret;
            }
        }
    }

    delete local_full_path;
    return fxn_ret;

}

int watdfs_cli_open(void *userdata, const char *path, struct fuse_file_info *fi) {
    DLOG("watdfs_cli_open called for '%s'", path);

    int fxn_ret = 0;
    int rpc_ret = 0;
    // struct stat server_statbuf;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        fxn_ret = -EMFILE;
        goto cleanup;
    }

    // rpc_ret = getattr_rpc(userdata, path, &server_statbuf);

    rpc_ret = download_to_client(userdata, path);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        goto cleanup;
    }
    rpc_ret = open_rpc(userdata, path, fi);
    DLOG("Open rpc in open returns: %d", rpc_ret);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
        goto cleanup;
    }
    // }
    
    
    rpc_ret = open(local_full_path, fi->flags);
    if (rpc_ret < 0) {
        fxn_ret = rpc_ret;
    } else {
        DLOG(" STORED TO CAHCE WHEN WRITE");
        struct client_meta *client = (client_meta *)userdata;
        DLOG("local full path: %s", local_full_path);
        // struct file_meta meta;
        (client->cache)[std::string(local_full_path)] = new file_meta;
        (client->cache)[std::string(local_full_path)]->fh = rpc_ret;
        (client->cache)[std::string(local_full_path)]->flags = fi->flags;
        (client->cache)[std::string(local_full_path)]->tc = time(0);
        (client->cache)[std::string(local_full_path)]->server_fh= fi->fh;
    }
    

cleanup:
    delete local_full_path;
    return fxn_ret;
}



int watdfs_cli_release(void *userdata, const char *path, struct fuse_file_info *fi) {
    DLOG("watdfs_cli_release started");
    
    int rpc_ret = 0;
    int fxn_ret = 0;
    int client_fh;
    char *local_full_path = get_full_path(userdata, path);
    struct client_meta *client = (struct client_meta *)userdata;

    if (!is_file_open(userdata, local_full_path)) {
      goto cleanup;
    }


    if ((fi->flags & O_ACCMODE) != O_RDONLY) { // file was opened in write mode
        // the file should be flushed from the client to the server
        DLOG("File already opened in write mode %s", path);
        lock_rpc(path, RW_WRITE_LOCK);
        rpc_ret = upload_to_server(userdata, path);
        // unlock_rpc(path, RW_WRITE_LOCK);
        if (rpc_ret < 0) {
            DLOG("upload to server failed with rpc_ret = %d", rpc_ret);
            fxn_ret = rpc_ret;
            goto cleanup;
        }
    }
    DLOG("release_rpc called in cli_release");
    rpc_ret = release_rpc(userdata, path, fi);

    // close file but don't erase cache entries
    client_fh = get_fh(userdata, local_full_path);
    close(client_fh);
    (client->cache).erase(std::string(local_full_path));
    

cleanup:
    delete local_full_path;
    return fxn_ret;

}


int watdfs_cli_read(void *userdata, const char *path, char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    DLOG("watdfs_cli_read called for '%s'", path);
    
    int rpc_ret = 0;
    int fxn_ret = 0;
    int client_fh;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        // freshness check under read only mode
        if (get_file_flags(userdata, local_full_path) == O_RDONLY) {
            if (!check_update_freshness_condition(userdata, path)) {
                // struct stat server_statbuf;
                // getattr_rpc(userdata, path, &server_statbuf);
                DLOG("cli read downalod");
                rpc_ret = download_to_client(userdata, path);
                if (rpc_ret < 0) {
                    fxn_ret = rpc_ret;
                    goto cleanup;
                }
                update_tc(userdata, path);
            }
        }
        client_fh = get_fh(userdata, local_full_path);
        rpc_ret = pread(client_fh, buf, size, offset);
        if (rpc_ret < 0) {
            fxn_ret = rpc_ret;
            goto cleanup;
        } else {
            fxn_ret = rpc_ret;
        }

    } else {
        fxn_ret = -1;
    }

cleanup:
    delete local_full_path;
    return fxn_ret;
}

int watdfs_cli_write(void *userdata, const char *path, const char *buf,
                     size_t size, off_t offset, struct fuse_file_info *fi) {
    DLOG("watdfs_cli_write started");
    int rpc_ret = 0;
    int fxn_ret = 0;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        // if (get_file_flags(userdata, local_full_path) == O_RDONLY) {
        //     fxn_ret = -EMFILE;
        // } else {
        int client_fh = get_fh(userdata, local_full_path);
        int sys_ret = pwrite(client_fh, buf, size, offset);
        if (sys_ret < 0) {
            DLOG("write failed for client");
            fxn_ret = sys_ret;
            goto cleanup;
        } else {    // write succeeded
            fxn_ret = sys_ret;
            if (!check_update_freshness_condition(userdata, path)) {
                lock_rpc(path, RW_WRITE_LOCK);
                rpc_ret = upload_to_server(userdata, path);
                // unlock_rpc(path, RW_WRITE_LOCK);
                if (rpc_ret < 0) {
                    fxn_ret = rpc_ret;
                }
                // update local file metadata no matter file transfering was successful or not
                update_tc(userdata, path);
            }
        }
        // }

    } else {
        fxn_ret = -1;
    }

cleanup:   
    delete local_full_path;
    return fxn_ret;
}

int watdfs_cli_truncate(void *userdata, const char *path, off_t newsize) {
    DLOG("cli_truncate started");
    int rpc_ret = 0;
    int fxn_ret = 0;
    
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        if (get_file_flags(userdata, local_full_path) == O_RDONLY) {
            fxn_ret = -EMFILE;
            goto cleanup;
        }
        // write mode
        int sys_ret = truncate(local_full_path, newsize); 
        if (sys_ret < 0) {
            fxn_ret = sys_ret ;
        } else if (!check_update_freshness_condition(userdata, path)) {
            lock_rpc(path, RW_WRITE_LOCK);
            rpc_ret = upload_to_server(userdata, path);
            // unlock_rpc(path, RW_WRITE_LOCK);
            update_tc(userdata, path);
            if (rpc_ret < 0) {
                fxn_ret = rpc_ret;
                goto cleanup;
            }
        }
        
    } else {
        // struct stat server_statbuf;
        // DLOG("cli_truncate getattr_rpc");
        // getattr_rpc(userdata, path, &server_statbuf);
        DLOG("cli_truncate download");
        rpc_ret = download_to_client(userdata, path);
        if (rpc_ret < 0) {
            fxn_ret = rpc_ret;
            goto cleanup;
        }
        int client_fh = open(local_full_path, O_RDWR);
        if (client_fh < 0) {
            fxn_ret = client_fh;
            goto cleanup;
        }
        int sys_ret = truncate(local_full_path, newsize); 
        if (sys_ret < 0) {
            fxn_ret = sys_ret;
        }

    }

cleanup:
    delete local_full_path;
    return fxn_ret;

}

int watdfs_cli_fsync(void *userdata, const char *path, struct fuse_file_info *fi) {
    DLOG("watdfs_cli_fsync started");
    
    int fxn_ret = 0;
    char *local_full_path = get_full_path(userdata, path);

    lock_rpc(path, RW_WRITE_LOCK);
    fxn_ret = upload_to_server(userdata, path);
    // unlock_rpc(path, RW_WRITE_LOCK);

    // check error
    if (fxn_ret >= 0) {
        update_tc(userdata, path);
    }

    delete local_full_path;
    return fxn_ret;

}

// CHANGE METADATA
int watdfs_cli_utimensat(void *userdata, const char *path, const struct timespec ts[2]) {
    DLOG("watdfs_cli_utimens started"   );

    int rpc_ret = 0;
    int fxn_ret = 0;
    // struct stat server_statbuf;
    char *local_full_path = get_full_path(userdata, path);

    if (is_file_open(userdata, local_full_path)) {
        if (get_file_flags(userdata, local_full_path) == O_RDONLY) { // write calls are not allowed
            fxn_ret = -EMFILE;
            goto cleanup;
        } 

        int sys_ret = utimensat(0, local_full_path, ts, 0); 
        if (sys_ret < 0) {
            fxn_ret = sys_ret;
            goto cleanup;
        }
        if (!check_update_freshness_condition(userdata, path)) {
            lock_rpc(path, RW_WRITE_LOCK);
            rpc_ret = upload_to_server(userdata, path);
            // unlock_rpc(path, RW_WRITE_LOCK);
            if (rpc_ret < 0) {
                fxn_ret = rpc_ret;
            }
        }
        
    } else {
        // rpc_ret = getattr_rpc(userdata, path, &server_statbuf);
        // if (rpc_ret < 0) {
        //     fxn_ret = rpc_ret;
        //     goto cleanup;
        // }

        rpc_ret = download_to_client(userdata, path);
        int client_fh = open(local_full_path, O_RDWR);
        if (client_fh < 0) {
            fxn_ret = client_fh;
            goto cleanup;
        } 

        int sys_ret = utimensat(0, local_full_path, ts, 0); 
        if (sys_ret < 0) {
            fxn_ret = sys_ret;
        }
    }

cleanup:
    delete local_full_path;
    return fxn_ret;

}


