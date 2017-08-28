/*
 * This is a dummy device driver used for testing misc stuff for Syzkaller
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define  DEVICE_NAME "dummychar"
#define  CLASS_NAME  "dummy"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tchibo");
MODULE_DESCRIPTION("A dummy module for testing KCOV and fuzzing");

static int    majorNumber;
static char   message[256] = {0};
static short  size_of_message;
static int    numberOpens = 0;
static struct class*  dummy_class  = NULL;
static struct device* dummy_device = NULL;

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static ssize_t dev_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations fops =
{
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
	.unlocked_ioctl = dev_ioctl,
};

static char *dummy_devnode(struct device *dev, umode_t *mode) {
	if (mode) {
		*mode = 0777;
	}
	return NULL;
}

static int __init dummy_init(void){
	printk(KERN_INFO "dummy_Char: Initializing the dummy_Char LKM\n");

	// Try to dynamically allocate a major number for the device -- more difficult but worth it
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0){
		printk(KERN_ALERT "dummy_Char failed to register a major number\n");
		return majorNumber;
	}
	printk(KERN_INFO "dummy_Char: registered correctly with major number %d\n", majorNumber);

	// Register the device class
	dummy_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(dummy_class)){                // Check for error and clean up if there is
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class\n");
		return PTR_ERR(dummy_class);          // Correct way to return an error on a pointer
	}
	dummy_class->devnode = dummy_devnode;
	printk(KERN_INFO "dummy_Char: device class registered correctly\n");

	// Register the device driver
	dummy_device = device_create(dummy_class, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(dummy_device)) {
		class_destroy(dummy_class);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device\n");
		return PTR_ERR(dummy_device);
	}
	printk(KERN_INFO "dummy_Char: device class created correctly\n");
	return 0;
}

static void __exit dummy_exit(void){
	device_destroy(dummy_class, MKDEV(majorNumber, 0));     // remove the device
	class_unregister(dummy_class);                          // unregister the device class
	class_destroy(dummy_class);                             // remove the device class
	unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
	printk(KERN_INFO "dummy_Char: Goodbye!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
	numberOpens++;
	printk(KERN_INFO "dummy_Char: Device has been opened %d time(s)\n", numberOpens);
	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	printk(KERN_INFO "dummy_Char: Read called with length: %d\n", len);
	ssize_t asd = 0;
	ssize_t abc = 0;
	switch (len) {
	case 0x12:
		asd = 31;
		break;
	case 0x19:
		asd = 1;
		break;
	case 0x32:
		asd = 2;
		break;
	case 0x42:
		asd = 3;
		break;
	case 0x99:
		asd = 4;
		break;
	}
	if (len == 0x66) {
		asd = 5;
		abc = 3;
		// needed to generate a call to trace_pc
		asm volatile ("");
	}
	if (len == 0x77) {
		asd = 6;
		abc = 4;
		asm volatile ("");
	}
	if (len == 0x88) {
		asd = 7;
		abc = 10;
		asm volatile ("");
	}
	return asd + abc;
}

noinline void set_ptr(long *p, long val) {
	*p = val;
}

struct innest_struct {
	unsigned int x;
};

struct inner_struct {
	unsigned int a[3];
	struct innest_struct s;
};

struct write_struct {
	unsigned char byte_field;
	unsigned short word_field;
	unsigned int dword_field;
	unsigned long qword_field;
	struct inner_struct s;
};

static ssize_t dev_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset) {
	printk(KERN_INFO "dummy_Char: dev_write invoked\n");
	long res = 0;
	int i;
	char tmp[100];
	for (i = 0 ; i < 100 ; ++i) {
		tmp[i] = 0;
	}
	copy_from_user(tmp, buffer, sizeof(struct write_struct));
	struct write_struct *s = (struct write_struct *) tmp;
	if (s->byte_field == 0xab) {
		set_ptr(&res, 1);
	} else {
		set_ptr(&res, -1);
	}
	if (s->word_field == 0xabab) {
		set_ptr(&res, 2);
		if (s->dword_field == 0xabababab) {
			set_ptr(&res, 3);
			if (s->qword_field == 0xababababababab) {
				set_ptr(&res, 4);
				if (s->s.s.x == 0xdeadbeef) {
					set_ptr(&res, 5);
					if (s->s.a[0] == 0x11111111) {
						set_ptr(&res, 6);
						if (s->s.a[1] == 0x22222222) {
							set_ptr(&res, 7);
							if (s->s.a[2] == 0x33333333) {
								set_ptr(&res, 8);
							} else {
								set_ptr(&res, -8);
							}
						} else {
							set_ptr(&res, -7);
						}
					} else {
						set_ptr(&res, -6);
					}
				} else {
					set_ptr(&res, -5);
				}
			} else {
				set_ptr(&res, -4);
			}
		} else {
			set_ptr(&res, -3);
		}
	} else {
		set_ptr(&res, -2);
	}
	return (ssize_t) res;
}

static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long res = 0;
	switch (cmd) {
	case 0xdeadbeef:
		if (arg == 0x12345678) {
			set_ptr(&res, 1);
			asm volatile ("");
		} else {
			set_ptr(&res, 2);
			asm volatile ("");
		}
		break;
	case 0xcafebabe:
		if (arg == 0x87654321) {
			set_ptr(&res, 3);
			asm volatile ("");
		} else {
			set_ptr(&res, 4);
			asm volatile ("");
		}
		break;
	case 0xdeaddead:
		if (arg == 0x45678901) {
			set_ptr(&res, 5);
			asm volatile ("");
		} else {
			set_ptr(&res, 6);
			asm volatile ("");
		}
		break;
	case 0xfacefeed:
		if (arg == 0x11111111) {
			set_ptr(&res, 7);
			asm volatile ("");
		} else {
			set_ptr(&res, 8);
			asm volatile ("");
		}
		break;
	}
	return res;
}
static int dev_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "dummy_Char: Device successfully closed\n");
	return 0;
}

module_init(dummy_init);
module_exit(dummy_exit);
