/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/cdev.h>
#include <linux/cred.h>  // for current_uid();
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>    // included for __init and __exit macros
#include <linux/kernel.h>  // included for KERN_INFO
#include <linux/module.h>  // included for all kernel modules
#include <linux/proc_fs.h>
#include <linux/sched.h>  // task_struct requried for current_uid()
#include <linux/seq_file.h>
#include <linux/slab.h>  // for kmalloc/kfree
#include <linux/string.h>
#include <linux/uaccess.h>  // copy_to_user

#include "maze.h"

// DEFINE_MUTEX(maze_mutex);

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

// Define the maze structure
static struct {
    maze_t maze;
    int created;
    pid_t pid;
} mazes[_MAZE_MAXUSER] = {0};

static int find_maze_slot(pid_t pid) {
    if (pid == 0) {
        for (int i = 0; i < _MAZE_MAXUSER; i++) {  // Find the first empty slot
            if (mazes[i].created != 1)
                return i;
        }
    } else {  // Find the slot with the given PID
        for (int i = 0; i < _MAZE_MAXUSER; i++) {
            if ((mazes[i].created) && (mazes[i].pid == pid))
                return i;
        }
    }
    return -1;  // No available slot found
}

// initialize a maze slot
static void init_maze_slot(int index, int pid) {
    memset(&mazes[index].maze, 0, sizeof(maze_t));
    mazes[index].created = 1;
    mazes[index].pid = pid;
}

void carve_path(int x, int y, int w, int h, int index) {
    maze_t *maze = &mazes[index].maze;
    // Define the four possible directions in which we can carve paths
    int directions[4][2] = {{1, 0}, {-1, 0}, {0, 1}, {0, -1}};
    // Randomize the directions
    for (int i = 0; i < 4; ++i) {
        int j = get_random_u32() % 4;
        int temp[2] = {directions[i][0], directions[i][1]};
        directions[i][0] = directions[j][0];
        directions[i][1] = directions[j][1];
        directions[j][0] = temp[0];
        directions[j][1] = temp[1];
    }
    // Try each direction
    for (int i = 0; i < 4; ++i) {
        int dx = directions[i][0];
        int dy = directions[i][1];
        int x2 = x + (dx * 2);
        int y2 = y + (dy * 2);
        if (x2 > 0 && x2 < w && y2 > 0 && y2 < h && maze->blk[y2][x2] == 1) {
            maze->blk[y2 - dy][x2 - dx] = 0;
            maze->blk[y2][x2] = 0;
            carve_path(x2, y2, w, h, index);
        }
    }
}

void generate_maze(int w, int h, int index) {
    maze_t *maze = &mazes[index].maze;
    // Initialize the maze with walls
    for (int y = 0; y <= h; ++y) {
        for (int x = 0; x <= w; ++x) {
            maze->blk[y][x] = 1;
        }
    }
    carve_path(1, 1, w, h, index);
}

static int maze_dev_open(struct inode *i, struct file *f) {
    // printk(KERN_INFO "maze: device opened.\n");
    return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {
    // printk(KERN_INFO "maze: device closed. %d\n", current->pid);
    int slot_index = find_maze_slot(current->pid);
    if (slot_index != -1) {
        mazes[slot_index].created = 0;
    }
    return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    // printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
    int index = find_maze_slot(current->pid);
    if (index == -1) return ENOENT;

    maze_t *maze = &mazes[index].maze;

    char *maze_layout = kmalloc(maze->w * maze->h, GFP_KERNEL);

    for (int i = 0; i < maze->h; i++) {
        memcpy(maze_layout + i * maze->w, maze->blk[i], maze->w);
    }

    if (copy_to_user(buf + *off, maze_layout, maze->w * maze->h)) {
        kfree(maze_layout);
        return EBUSY;
    }

    *off += maze->w * maze->h;

    kfree(maze_layout);
    return maze->w * maze->h;
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    // printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);
    int index = find_maze_slot(current->pid);
    if (index == -1) return ENOENT;

    maze_t *maze = &mazes[index].maze;
    coord_t *moves;
    moves = kmalloc(len, GFP_KERNEL);
    if (copy_from_user(moves, (coord_t *)buf, len)) {
        kfree(moves);
        return -EBUSY;
    }

    // mutex_lock(&maze_mutex);

    size_t size = len / sizeof(coord_t);
    for (size_t i = 0; i < size; i++) {
        coord_t move = moves[i];

        int new_x = maze->cx + move.x;
        int new_y = maze->cy + move.y;
        if (new_x < 0 || new_x >= maze->w || new_y < 0 || new_y >= maze->h || maze->blk[new_y][new_x] == 1) {
            continue;
        }
        maze->cx = new_x;
        maze->cy = new_y;
    }
    // mutex_unlock(&maze_mutex);
    kfree(moves);

    return 0;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    // printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
    int slot_index;
    pid_t current_pid = current->pid;
    // char tmp_maze[maze_size.x + 1][maze_size.y + 1];

    switch (cmd) {
        case MAZE_CREATE:
            // mutex_lock(&maze_mutex);
            coord_t maze_size;
            if (copy_from_user(&maze_size, (coord_t *)arg, sizeof(coord_t))) {
                printk(KERN_ERR "maze_create: failed to copy maze size from user space.\n");
                // mutex_unlock(&maze_mutex);
                return EBUSY;
            }

            if (maze_size.x < 3 || maze_size.y < 3 || maze_size.x > _MAZE_MAXX || maze_size.y > _MAZE_MAXY) {
                printk(KERN_ERR "maze_create(%d, %d): invalid maze size.\n", maze_size.x, maze_size.y);
                // mutex_unlock(&maze_mutex);
                return EINVAL;
            }

            // Check if a maze has already been created for the calling process
            slot_index = find_maze_slot(current_pid);
            if (slot_index != -1) {
                printk(KERN_ERR "maze_create: maze already created for PID %d.\n", current_pid);
                // mutex_unlock(&maze_mutex);
                return EEXIST;
            }

            // Check if there are already _MAZE_MAXUSER mazes created
            slot_index = find_maze_slot(0);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_create: maximum number of mazes reached.\n");
                // mutex_unlock(&maze_mutex);
                return ENOMEM;
            }

            // Initialize the maze
            init_maze_slot(slot_index, current_pid);
            mazes[slot_index].maze.w = maze_size.x;
            mazes[slot_index].maze.h = maze_size.y;

            // Generate maze
            generate_maze(maze_size.x, maze_size.y, slot_index);

            // Initialize start and end positions
            while ((mazes[slot_index].maze.sx == mazes[slot_index].maze.ex && mazes[slot_index].maze.sy == mazes[slot_index].maze.ey) || (mazes[slot_index].maze.blk[mazes[slot_index].maze.sy][mazes[slot_index].maze.sx] == 1) || (mazes[slot_index].maze.blk[mazes[slot_index].maze.ey][mazes[slot_index].maze.ex] == 1)) {
                mazes[slot_index].maze.sx = get_random_u32() % (maze_size.x - 2) + 1;
                mazes[slot_index].maze.sy = get_random_u32() % (maze_size.y - 2) + 1;
                mazes[slot_index].maze.ex = get_random_u32() % (maze_size.x - 2) + 1;
                mazes[slot_index].maze.ey = get_random_u32() % (maze_size.y - 2) + 1;
            }
            mazes[slot_index].maze.cx = mazes[slot_index].maze.sx;
            mazes[slot_index].maze.cy = mazes[slot_index].maze.sy;

            printk(KERN_INFO "maze_create: maze created for PID %d.\n", current_pid);
            // mutex_unlock(&maze_mutex);
            return 0;

        case MAZE_RESET:
            // Find the maze associated with the current process
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_reset: there is no maze to reset.\n");
                return ENOENT;  // No maze associated with the process
            }
            // Reset the player's position to the start position
            mazes[slot_index].maze.cx = mazes[slot_index].maze.sx;
            mazes[slot_index].maze.cy = mazes[slot_index].maze.sy;
            printk(KERN_INFO "maze_reset: player position reset to start position.\n");
            return 0;

        case MAZE_DESTROY:
            // Find the maze associated with the current process
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_destroy: there is no maze to destroy.\n");
                return ENOENT;  // No maze associated with the process
            }
            // Destroy the maze by marking it as unused
            mazes[slot_index].created = 0;
            printk(KERN_INFO "maze_destroy: maze destroyed.\n");
            return 0;

        case MAZE_GETSIZE:
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_getsize: there is no maze to get size.\n");
                return ENOENT;  // No maze associated with the process
            }
            // Copy the size of the maze to the user-space pointer
            coord_t size = {.x = mazes[slot_index].maze.w, .y = mazes[slot_index].maze.h};
            if (copy_to_user((coord_t *)arg, &size, sizeof(coord_t))) {
                printk(KERN_ERR "maze_getsize: failed to copy maze size to user space.\n");
                return EBUSY;
            }
            return 0;

        case MAZE_MOVE:
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_move: there is no maze to move.\n");
                return ENOENT;  // No maze associated with the process
            }
            coord_t move;
            if (copy_from_user(&move, (coord_t *)arg, sizeof(coord_t))) {
                printk(KERN_ERR "maze_move: failed to copy move from user space.\n");
                return EBUSY;
            }
            // Check if the move is valid
            maze_t *maze = &mazes[slot_index].maze;
            if ((move.x && move.y) || !(move.x || move.y) || move.x > 1 || move.y > 1 || move.x < -1 || move.y < -1) {
                // Invalid move, return without updating player position
                printk(KERN_ERR "maze_move(%d, %d): invalid move.\n", move.x, move.y);
                return EINVAL;
            } else if (maze->blk[maze->cy + move.y][maze->cx + move.x] == 1) {
                printk(KERN_INFO "maze_move(%d, %d): hit a wall.\n", move.x, move.y);
                return 0;  // Move hits a wall
            }

            // Update player position
            maze->cx += move.x;
            maze->cy += move.y;
            // printk(KERN_INFO "# %02d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
            //        slot_index, maze->w, maze->h, maze->sx, maze->sy, maze->ex, maze->ey, maze->cx, maze->cy);
            return 0;

        case MAZE_GETPOS:
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_getpos: there is no maze to get position.\n");
                return ENOENT;  // No maze associated with the process
            }

            // Get the player's position from the maze structure
            coord_t pos;
            pos.x = mazes[slot_index].maze.cx;
            pos.y = mazes[slot_index].maze.cy;

            // Copy the position to user space
            if (copy_to_user((coord_t *)arg, &pos, sizeof(coord_t))) {
                printk(KERN_ERR "maze_getpos: failed to copy current position to user space.\n");
                return EBUSY;
            }
            return 0;

        case MAZE_GETSTART:
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_getstart: there is no maze to get start position.\n");
                return ENOENT;  // No maze associated with the process
            }

            // Get the start position from the maze structure
            coord_t start_pos;
            start_pos.x = mazes[slot_index].maze.sx;
            start_pos.y = mazes[slot_index].maze.sy;

            // Copy the start position to user space
            if (copy_to_user((coord_t *)arg, &start_pos, sizeof(coord_t))) {
                printk(KERN_ERR "maze_getstart: failed to copy start position to user space.\n");
                return EBUSY;
            }
            return 0;

        case MAZE_GETEND:
            slot_index = find_maze_slot(current_pid);
            if (slot_index == -1) {
                printk(KERN_ERR "maze_getend: there is no maze to get end position.\n");
                return ENOENT;  // No maze associated with the process
            }

            // Get the start position from the maze structure
            coord_t end_pos;
            end_pos.x = mazes[slot_index].maze.ex;
            end_pos.y = mazes[slot_index].maze.ey;

            // Copy the start position to user space
            if (copy_to_user((coord_t *)arg, &end_pos, sizeof(coord_t))) {
                printk(KERN_ERR "maze_getend: failed to copy end position to user space.\n");
                return EBUSY;
            }
            return 0;

        default:
            printk(KERN_ERR "maze: invalid IOCTL command.\n");
            return EINVAL;
    }
    return 0;
}

static const struct file_operations maze_dev_fops = {
    .owner = THIS_MODULE,
    .open = maze_dev_open,
    .read = maze_dev_read,
    .write = maze_dev_write,
    .unlocked_ioctl = maze_dev_ioctl,
    .release = maze_dev_close};

static int maze_proc_read(struct seq_file *m, void *v) {
    char buf[128];

    // Lock to prevent concurrent access to maze data
    // mutex_lock(&maze_mutex);
    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i].created) {
            // Format maze information into a buffer
            snprintf(buf, sizeof(buf), "#%02d: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
                     i, mazes[i].pid, mazes[i].maze.w, mazes[i].maze.h, mazes[i].maze.sx, mazes[i].maze.sy,
                     mazes[i].maze.ex, mazes[i].maze.ey, mazes[i].maze.cx, mazes[i].maze.cy);
            seq_printf(m, buf);
            for (int j = 0; j < mazes[i].maze.h; j++) {
                snprintf(buf, sizeof(buf), "- %03d: ", j);
                seq_printf(m, buf);
                for (int k = 0; k < mazes[i].maze.w; k++) {
                    if (j == mazes[i].maze.cy && k == mazes[i].maze.cx)
                        snprintf(buf, sizeof(buf), "*");
                    else if (j == mazes[i].maze.sy && k == mazes[i].maze.sx)
                        snprintf(buf, sizeof(buf), "S");
                    else if (j == mazes[i].maze.ey && k == mazes[i].maze.ex)
                        snprintf(buf, sizeof(buf), "E");
                    else if (mazes[i].maze.blk[j][k] == 1) {
                        snprintf(buf, sizeof(buf), "#");
                    } else {
                        snprintf(buf, sizeof(buf), ".");
                    }
                    seq_printf(m, buf);
                }
                snprintf(buf, sizeof(buf), "\n");
                seq_printf(m, buf);
            }
            seq_printf(m, "\n");
        } else {
            snprintf(buf, sizeof(buf), "#%02d: vacancy\n\n", i);
            seq_printf(m, buf);
        }
    }

    // Unlock mutex
    // mutex_unlock(&maze_mutex);

    return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
    .proc_open = maze_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
    if (mode == NULL) return NULL;
    *mode = 0666;
    return NULL;
}

static int __init maze_init(void) {
    // create char dev
    if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
        return -1;
    if ((clazz = class_create("upclass")) == NULL)
        goto release_region;
    clazz->devnode = maze_devnode;
    if (device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
        goto release_class;
    cdev_init(&c_dev, &maze_dev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1)
        goto release_device;

    // create proc
    proc_create("maze", 0, NULL, &maze_proc_fops);

    // printk(KERN_INFO "maze: initialized.\n");
    return 0;  // Non-zero return means that the module couldn't be loaded.

release_device:
    device_destroy(clazz, devnum);
release_class:
    class_destroy(clazz);
release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit maze_cleanup(void) {
    remove_proc_entry("maze", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cheng-Yu Wu");
MODULE_DESCRIPTION("The unix programming course maze kernel module.");
