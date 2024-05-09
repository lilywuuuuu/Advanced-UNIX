#define _GNU_SOURCE 
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

FILE *(*original_fopen)(const char *filename, const char *mode) = NULL;
size_t (*original_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
size_t (*original_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
int (*original_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
int (*original_system)(const char *command) = NULL;

void init() __attribute__((constructor));
void fini() __attribute__((destructor)); 

void init() {
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fread = dlsym(RTLD_NEXT, "fread");
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_connect = dlsym(RTLD_NEXT, "connect");
    original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    original_system = dlsym(RTLD_NEXT, "system");
}

int logflag = 1; 
FILE *logfile; 
char *writemode = "w"; 
char opened_file[100]; 
char log_content[100]; 

void logoutput(char *content, const char *output_file){
    if (strcmp(output_file, "no_file") == 0){
        fprintf(stderr, content);
    } else {
        logfile = original_fopen(output_file, writemode); 
        if (logflag) {
            logflag = 1; 
            writemode = "a"; 
        }
        fprintf(logfile, content); 
        fclose(logfile); 
    }
}

char *modify_logname(){
    char *modified_name = strrchr(opened_file, '/'); // find the last '/'
    if (modified_name != NULL){ // there is a '/'
        modified_name++; // move to the letter after /
    } else { // there is no '/'
        modified_name = opened_file; // use the whole name
    }

    char *dot = strchr(modified_name, '.');  // find the first dot
    if (dot != NULL){
        *dot = '\0'; 
    }

    return modified_name; 
}

void pidlog(char* content, char* type){
    pid_t pid = getpid(); 
    char *modified_filename = modify_logname(); 
    char readlogname[100];
    snprintf(readlogname, sizeof(readlogname), "logs/%d-%s-%s.log", pid, modified_filename, type); 
    FILE *readlogfile = original_fopen(readlogname, "a"); 
    fprintf(readlogfile, "%s\n", content); 
}

FILE *fopen(const char *filename, const char *mode) {
    strcpy(opened_file, filename); 
    const char *bl = getenv("OPEN_BL");
    const char *output_file = getenv("LOGGER_OUTPUT"); 
    char buf[100] = ""; 
    int index = 0; 
    for(int i=0; i<strlen(bl); i++){ // parse through blacklist
        if(bl[i] != ' '){
            buf[index++] = bl[i];
        } else {
            int flag = 1; 
            for (int j=0; j<index; j++){
                if (buf[j] == '*') {
                    break; 
                } else if (buf[j] != filename[j]){ // not on blacklist
                    flag = 0; 
                    break; 
                }
            }
            if (flag) { // on blacklist
                snprintf(log_content, 100, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", filename, mode);
                logoutput(log_content, output_file); 
                errno = EACCES; 
                return NULL; 
            }
            memset(buf, 0, sizeof(buf));
            index = 0; 
        }
    } 
    FILE *fp = original_fopen(filename, mode);
    snprintf(log_content, 100, "[logger] fopen(\"%s\", \"%s\") = %p\n", filename, mode, fp);
    logoutput(log_content, output_file); 
    return fp;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *content = ptr; 
    long original_position = ftell(stream);
    int total_read = original_fread(content, size, nmemb, stream);
    const char *bl = getenv("READ_BL");
    const char *output_file = getenv("LOGGER_OUTPUT"); 
    char buf[100] = ""; 
    int index = 0; 
    for(int i=0; i<strlen(bl); i++){ // parse through blacklist
        if(bl[i] != ' '){
            buf[index++] = bl[i];
        } else {
            if (strstr(content, buf) != NULL) { // Check if data is in the blacklist
                snprintf(log_content, 100, "[logger] fread(%p, %lu, %lu, %p) = 0\n", ptr, size, nmemb, stream);
                logoutput(log_content, output_file); 
                memset(ptr, 0, strlen(ptr));
                errno = EACCES;
                return 0;
            }
            memset(buf, 0, sizeof(buf));
            index = 0; 
        }
    } 
    fseek(stream, original_position, SEEK_SET); // reset file position indicator
    total_read = original_fread(ptr, size, nmemb, stream);
    snprintf(log_content, sizeof(log_content), "[logger] fread(%p, %lu, %lu, %p) = %lu\n", ptr, size, nmemb, stream, total_read);
    logoutput(log_content, output_file);
    pidlog(ptr, "read");  
    return total_read;
} 

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t len = strlen(ptr);
    char* str = (char*)malloc((len * 2) + 1);
    char* content = (char*)malloc((len * 2) + 1);
    snprintf(content, len + 1, "%s", (char *)ptr); 
    const char *output_file = getenv("LOGGER_OUTPUT");

    int index = 0;
    for (size_t i = 0; i < len; i++) { 
        if (content[i] == '\n') {
            str[index++] = '\\';
            str[index++] = 'n';
        } else {
            str[index++] = content[i];
        }
    }
    str[index] = '\0';  

    if(stream == NULL) {
        snprintf(log_content, 100, "[logger] fwrite(\"%s\", %lu, %lu, %p) = 0\n", str, size, nmemb, stream);
        logoutput(log_content, output_file);
        errno = EACCES; 
        return 0; 
    }

    const char *bl = getenv("WRITE_BL");
    char buf[100] = ""; 
    index = 0; 
    for(int i=0; i<strlen(bl); i++){ // parse through blacklist
        if(bl[i] != ' '){
            buf[index++] = bl[i];
        } else {
            int flag = 1; 
            for (int j=0; j<index; j++){
                if (buf[j] == '*') {
                    break; 
                } else if (buf[j] != opened_file[j]){ // not on blacklist
                    flag = 0; 
                    break; 
                }
            }
            if (flag) { // on blacklist
                snprintf(log_content, 100, "[logger] fwrite(\"%s\", %lu, %lu, %p) = 0\n", str, size, nmemb, stream);
                logoutput(log_content, output_file);
                errno = EACCES; 
                return 0; 
            }
            memset(buf, 0, sizeof(buf));
            index = 0; 
        }
    } 
         
    size_t result = original_fwrite(ptr, size, nmemb, stream); 
    snprintf(log_content, 100, "[logger] fwrite(\"%s\", %lu, %lu, %p) = %lu\n", str, size, nmemb, stream, result);
    logoutput(log_content, output_file);
    if (str[nmemb - 1] == '\\') nmemb++; 
    str[nmemb] = '\0'; 
    pidlog(str, "write"); 
    return result;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    char ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr_in->sin_addr), ip_addr, INET_ADDRSTRLEN);
    const char *bl = getenv("CONNECT_BL");
    const char *output_file = getenv("LOGGER_OUTPUT");
    char buf[100] = ""; 
    int index = 0; 
    for(int i=0; i<strlen(bl); i++){ // parse through blacklist
        if(bl[i] != ' '){
            buf[index++] = bl[i];
        } else {
            if (strcmp(ip_addr, buf) == 0) { // Check if data is in the blacklist
                snprintf(log_content, 100, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, ip_addr, addrlen);
                logoutput(log_content, output_file);
                errno = ECONNREFUSED;
                return -1;
            }
            memset(buf, 0, sizeof(buf));
            index = 0; 
        }
    }
    int result = original_connect(sockfd, addr, addrlen); 
    snprintf(log_content, 100, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip_addr, addrlen, result);
    logoutput(log_content, output_file);
    return result;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) { 
    char str[100]; 
    if (service == NULL){ // replace (null) with (nil)
        snprintf(str, 6, "(nil)"); 
    } else {
        snprintf(str, sizeof(service), service); 
    }
    
    const char *bl = getenv("GETADDRINFO_BL");
    const char *output_file = getenv("LOGGER_OUTPUT"); 
    char buf[100] = ""; 
    int index = 0; 
    for(int i=0; i<strlen(bl); i++){ // parse through blacklist
        if(bl[i] != ' '){
            buf[index++] = bl[i];
        } else {
            if (strcmp(node, buf) == 0) { // Check if data is in the blacklist
                snprintf(log_content, 100, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = -2\n", node, str, hints, res);
                logoutput(log_content, output_file);
                errno = EAI_NONAME;
                return -2;
            }
            memset(buf, 0, sizeof(buf));
            index = 0; 
        }
    } 
    int result = original_getaddrinfo(node, service, hints, res);
    snprintf(log_content, 100, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n", node, str, hints, res, result);
    logoutput(log_content, output_file);
    return result;
}

int system(const char *command) {
    int result = original_system(command);
    const char *output_file = getenv("LOGGER_OUTPUT");
    snprintf(log_content, 100, "[logger] system(\"%s\") = %d\n", command, result);
    logoutput(log_content, output_file);
    return 0;
}
