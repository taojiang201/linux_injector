#ifndef __SCS_H__
#define __SCS_H__

#include <exception>
#include <pthread.h>
#include <semaphore.h>

class sem
{
public:
	sem();

	~sem();
	
	bool wait();
	
	bool post();


private:
	sem_t m_sem;
};

class locker
{
public:
	locker();

		~locker();

		int Lock();

		int lock();

		bool unlock();

		bool UnLock();


private:
	pthread_mutex_t m_mutex;
};

class cond
{
public:
	cond();
		
	~cond();

		bool wait();

		bool signal();

private:
	pthread_mutex_t m_mutex;
	pthread_cond_t m_cond;
};

#endif
