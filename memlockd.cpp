/*
 * Copyright (C) 2007-2012 Russell Coker <russell@coker.com.au>
 * Licensed under GPL v3
 */
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <dirent.h>

#define MAX_FILES 1024
#define PIDFILE "/var/run/memlockd.pid"

typedef struct file_data
{
  char *name;
  int fd;
  struct stat sb;
  void *start;
  int map_size;
} FILE_DATA;

FILE_DATA files[MAX_FILES];
FILE_DATA new_files[MAX_FILES];
int num_files = 0;
int num_new_files = 0;
const char * config = "/etc/memlockd.cfg";
int debug = 0;
int page_size = 0;
uid_t uid = 0;
gid_t gid = 0;

#define BUF_SIZE 1024

void log(int priority, const char * const format, ...)
{
  va_list argp;
  va_start(argp, format);
  if(debug)
  {
    vfprintf(stderr, format, argp);
    fprintf(stderr, "\n");
  }
  else
    vsyslog(priority, format, argp);
}

void unmap_file(FILE_DATA *data)
{
  munmap(data->start, data->sb.st_size);
  log(LOG_INFO, "Unmapped file %s", data->name);
}

void unmap_close_file(FILE_DATA *data)
{
  unmap_file(data);
  free(data->name);
  data->name = NULL;
  close(data->fd);
  data->fd = -1;
}

// return 1 if a file is mapped
int open_map(int fd, struct stat *sb, const char * const name)
{
  new_files[num_new_files].start = mmap(NULL, sb->st_size, PROT_READ, MAP_SHARED, fd, 0);
  if(new_files[num_new_files].start == MAP_FAILED)
  {
    log(LOG_ERR, "Error mmaping %s: %s", name, strerror(errno));
    close(fd);
    return 0;
  }
  if(mlock(new_files[num_new_files].start, sb->st_size) == -1)
  {
    log(LOG_ERR, "Can't lock memory for %s, error %s", name, strerror(errno));
    munmap(new_files[num_new_files].start, sb->st_size);
    close(fd);
    return 0;
  }
  if(sb->st_size % page_size)
    new_files[num_new_files].map_size = sb->st_size - (sb->st_size % page_size)
                                      + page_size;
  else
    new_files[num_new_files].map_size = sb->st_size;
  new_files[num_new_files].fd = fd;
  memcpy(&new_files[num_new_files].sb, sb, sizeof(struct stat));
  new_files[num_new_files].name = strdup(name);
  num_new_files++;
  log(LOG_INFO, "Mapped file %s", name);
  return 1;
}

// return 0 for no file mapped and 1 for file mapped
int open_file(const char * const name, int no_error_non_exist)
{
  int fd = open(name, O_RDONLY);
  if(fd == -1 && no_error_non_exist && errno == ENOENT)
    return 0;
  if(fd == -1)
  {
    log(LOG_ERR, "Can't open file %s", name);
    return 0;
  }
  struct stat sb;
  if(fstat(fd, &sb) == -1)
  {
    log(LOG_ERR, "Can't stat file %s", name);
    close(fd);
    return 0;
  }
  int i;
  for(i = 0; i < num_files; i++)
  {
    if(files[i].fd != -1 && files[i].sb.st_dev == sb.st_dev
      && files[i].sb.st_ino == sb.st_ino)
    {
      if(files[i].sb.st_size == sb.st_size
       && files[i].sb.st_mtime == sb.st_mtime)
      {
        memcpy(&new_files[num_new_files], &files[i], sizeof(FILE_DATA));
        files[i].fd = -1;
        files[i].name = NULL;
        num_new_files++;
        return 1;
      }
      else
      {
        memcpy(&new_files[num_new_files], &files[i], sizeof(FILE_DATA));
        close(fd);
        num_new_files++;
        files[i].fd = -1;
        files[i].name = NULL;
        unmap_file(&new_files[num_new_files - 1]);
        open_map(new_files[num_new_files - 1].fd
               , &new_files[num_new_files - 1].sb, name);
        return 1;
      }
    }
  }
  for(i = 0; i < num_new_files; i++)
  {
    if(new_files[i].fd != -1 && new_files[i].sb.st_ino == sb.st_ino)
    {
      close(fd);
      return 0;
    }
  }
  return open_map(fd, &sb, name);
}

void map_file_dependencies(const char * const name, int no_error_non_exist)
{
  if(!uid || !gid)
    return;
  int pipe_fd[2];
  
  if(pipe(pipe_fd) == -1)
  {
    log(LOG_ERR, "Can't create pipe, not recursing");
    uid = 0;
    return;
  }
  int rc = fork();
  if(rc == -1)
  {
    log(LOG_ERR, "Can't fork, not recursing");
    uid = 0;
    return;
  }
  if(!rc)
  {
    char buf[4096];

    close(pipe_fd[0]);
    close(1);
    if(dup2(pipe_fd[1], 1) == -1)
    {
      log(LOG_ERR, "Can't create pipe");
      exit(1);
    }
    if(setresgid(gid, gid, gid) == -1 || setresuid(uid, uid, uid) == -1)
    {
      log(LOG_ERR, "Can't set UID and GID");
      exit(1);
    }
    sprintf(buf, "/usr/bin/ldd %s", name);
    char *argv[3];
    argv[0] = strdup("/usr/bin/ldd");
    argv[1] = strdup(name);
    argv[2] = NULL;
    execv(argv[0], (char * const *)argv);
    log(LOG_ERR, "Can't exec ldd");
    exit(1);
  }
  close(pipe_fd[1]);
  FILE *fp = fdopen(pipe_fd[0], "r");
  if(!fp)
    return;

  char buf[4096];
  while(fgets(buf, sizeof(buf), fp))
  {
    char *tmp = strchr(buf, '/');
    if(!tmp)
      continue;
    strtok(tmp, " ");
    open_file(tmp, no_error_non_exist);
  }
  fclose(fp);
  wait(&rc);
}

void parse_config_file(const char * const config_name, int recurse_count)
{
  struct stat sbuf;
  if(stat(config_name, &sbuf))
  {
    log(LOG_ERR, "Can't stat \"%s\"", config_name);
    exit(1);
  }
  if(S_ISDIR(sbuf.st_mode))
  {
    log(LOG_INFO, "Entering config dir \"%s\"", config_name);
    DIR *dirp = opendir(config_name);
    if(!dirp)
    {
      log(LOG_ERR, "Can't open config file/dir %s", config_name);
      exit(1);
    }
    int rc;
    struct dirent entry, *res;
    while((rc = readdir_r(dirp, &entry, &res)) == 0 && res)
    {
      int len = strlen(entry.d_name);
      if(len > 4 && !strcmp(".cfg", &entry.d_name[len - 4]))
      {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/%s", config_name, entry.d_name);
        parse_config_file(buf, recurse_count);
      }
    }
    if(rc)
    {
      log(LOG_ERR, "readdir_r() error for \"%s\"", config_name);
      exit(1);
    }
    closedir(dirp);
    return;
  }
  log(LOG_INFO, "Parsing config file \"%s\"", config_name);
  FILE *fp = fopen(config_name, "r");
  char buf[BUF_SIZE];
  while(fgets(buf, BUF_SIZE, fp))
  {
    int len = strlen(buf) - 1;
    if(buf[0] == '#')
      continue;
    if(buf[len] == '\n')
      buf[len] = 0;
    const char *ptr = buf;
    int map_dependencies = 0, no_error_non_exist = 0;
    if(*ptr == '%')
    {
      if(recurse_count > 1)
      {
        log(LOG_ERR, "Too much recursion, won't process \"%s\"", ptr+1);
      }
      else
      {
        ptr++;
        log(LOG_INFO, "Recursion, entering \"%s\"", ptr);
        parse_config_file(ptr, recurse_count + 1);
        continue;
      }
    }
    if(*ptr == '?')
    {
       ptr++;
       no_error_non_exist = 1;
    }
    if(*ptr == '+')
    {
       ptr++;
       map_dependencies = 1;
    }
    if(*ptr == '?')
    {
       ptr++;
       no_error_non_exist = 1;
    }
    if(*ptr != '/')
      continue;
    open_file(ptr, no_error_non_exist);
    if(map_dependencies)
      map_file_dependencies(ptr, no_error_non_exist);
  }
  fclose(fp);
}

void parse_config(int)
{
  num_new_files = 0;
  parse_config_file(config, 0);
  for(int i = 0; i < num_files; i++)
  {
    if(files[i].fd != -1)
      unmap_close_file(&files[i]);
  }
  if(!num_new_files)
  {
    log(LOG_INFO, "No files to lock - exiting");
    exit(0);
  }
  memcpy(files, new_files, sizeof(FILE_DATA) * num_new_files);
  num_files = num_new_files;
  num_new_files = 0;
}

void usage()
{
  fprintf(stderr, "Usage: memlockd [-c config-file] [-d] [-f]\n"
                  "       -d is for debugging mode (running in foreground and no syslog)\n"
                  "       -f is for foreground mode with syslog logging\n");
  exit(1);
}
int main(int argc, char **argv)
{
  int c, foreground = 0;
  pid_t old_pid = 0;
  page_size = (int) sysconf(_SC_PAGESIZE);
  while(-1 != (c = getopt(argc, argv, "fdc:u:")) )
  {
    switch(char(c))
    {
      case '?':
      case ':':
        usage();
      break;
      case 'c':
        config = optarg;
      break;
      case 'd':
        debug = 1;
      break;
      case 'f':
        foreground = 1;
      break;
      case 'u':
        struct passwd *pw = getpwnam(optarg);
        if(!pw)
        {
          log(LOG_ERR, "Can't look up user %s", optarg);
          exit(1);
        }
        uid = pw->pw_uid;
        gid = pw->pw_gid;
        endpwent();
      break;
    }
  }

  openlog("memlockd", LOG_CONS | LOG_PID, LOG_DAEMON);

  int write_pidfile = 1;
  if(debug || foreground || getuid())
    write_pidfile = 0;

  if(!debug && !foreground)
    daemon(0, 0);
  else
    chdir("/");
  if(write_pidfile)
  {
    FILE *fp = fopen(PIDFILE, "r");
    char buf[20];
    if(fp)
    {
      if(fgets(buf, sizeof(buf), fp))
        old_pid = atoi(buf);
      else
        log(LOG_ERR, "Can't read pidfile " PIDFILE);
      fclose(fp);
    }
  }

  if(mlockall(MCL_CURRENT|MCL_FUTURE) == -1)
  {
    log(LOG_ERR, "Can't lock memory, exiting");
    exit(1);
  }
  parse_config(0);

  struct sigaction sa;
  sa.sa_sigaction = NULL;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_handler = parse_config;
  if(sigaction(SIGHUP, &sa, NULL))
    log(LOG_ERR, "Can't handle sighup");
  if(!debug)
  {
    FILE *fp = fopen(PIDFILE, "w");
    if(fp)
    {
      if(fprintf(fp, "%d", (int)getpid()) <= 0)
      {
        log(LOG_ERR, "Can't write to " PIDFILE);
        unlink(PIDFILE);
      }
      fclose(fp);
    }
    else
      log(LOG_ERR, "Can't open " PIDFILE " for writing");
  }
  if(old_pid)
    kill(old_pid, SIGKILL);
  while(1)
    sleep(3600);
  return 0;
}
