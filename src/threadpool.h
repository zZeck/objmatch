/*

    thread management for n64sym
    shygoo 2017
    License: MIT

*/

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <pthread.h>

class CThreadPool {
 public:
  using worker_routine_t = void *(*)(void *);

 private:
  using worker_context_t = struct {
    volatile bool bRunning;
    pthread_t pthread;
    worker_routine_t routine;
    void* param;
  };

  worker_context_t* m_Workers;
  int m_NumWorkers;

  pthread_mutex_t m_DefaultMutex{};

  static auto RoutineProc(void* _worker) -> void*;

 public:
  CThreadPool();
  ~CThreadPool();
  static auto GetNumCPUCores() -> int;

  void WaitForWorkers();
  void AddWorker(worker_routine_t routine, void* param);

  void LockDefaultMutex();
  void UnlockDefaultMutex();
};

#endif  // THREADPOOL_H
