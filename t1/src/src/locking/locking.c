#include "locking.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>

static unsigned long pthreads_thread_id(void );
static pthread_mutex_t *lock_cs;
static unsigned long pthreads_thread_id(void );
static void pthreads_locking_callback(int mode,int type,char *file,int line);

void thread_setup(void)
	{
	int i;

	lock_cs=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i=0; i<CRYPTO_num_locks(); i++)
		pthread_mutex_init(&(lock_cs[i]),NULL);
	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
	}

void thread_cleanup(void)
	{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lock_cs[i]));
	OPENSSL_free(lock_cs);
	}

static void pthreads_locking_callback(int mode, int type, char *file,
	     int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(lock_cs[type]));
	else
		pthread_mutex_unlock(&(lock_cs[type]));
}


static unsigned long pthreads_thread_id(void)
{
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}

