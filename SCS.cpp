#include "SCS.h"
sem::sem()
{
	if (sem_init(&m_sem, 0, 0) != 0)
	{
		throw std::exception();
	}
}
sem::~sem()
{
	sem_destroy(&m_sem);
}
bool sem::wait()
{
	return sem_wait(&m_sem) == 0;
}
bool sem::post()
{
	return sem_post(&m_sem) == 0;
}
locker::locker()
{
	pthread_mutexattr_t attr;
	// 设置成循环锁属性
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (pthread_mutex_init(&m_mutex, &attr) != 0)
	{
		throw std::exception();
	}
}
locker::~locker()
{
	pthread_mutex_destroy(&m_mutex);
}
int locker::Lock()
{
	return pthread_mutex_lock(&m_mutex) == 0;
}
int locker::lock()
{
	return pthread_mutex_lock(&m_mutex) == 0;
}
bool locker::unlock()
{
	return pthread_mutex_unlock(&m_mutex) == 0;
}
bool locker::UnLock()
{
	return pthread_mutex_unlock(&m_mutex) == 0;
}
cond::cond()
{
	if (pthread_mutex_init(&m_mutex, NULL) != 0)
	{
		throw std::exception();
	}
	if (pthread_cond_init(&m_cond, NULL) != 0)
	{
		pthread_mutex_destroy(&m_mutex);
		throw std::exception();
	}
}
cond::~cond()
{
	pthread_mutex_destroy(&m_mutex);
	pthread_cond_destroy(&m_cond);
}
bool cond::wait()
{
	int ret = 0;
	pthread_mutex_lock(&m_mutex);
	ret = pthread_cond_wait(&m_cond, &m_mutex);
	pthread_mutex_unlock(&m_mutex);
	return ret == 0;
}
bool cond::signal()
{
	return pthread_cond_signal(&m_cond) == 0;
}