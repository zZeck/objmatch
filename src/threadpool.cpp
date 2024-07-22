/*

    thread management for n64sym
    shygoo 2017
    License: MIT

*/

#include "threadpool.h"

#include <pthread.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#endif

CThreadPool::CThreadPool() : m_NumWorkers(GetNumCPUCores()) {
  m_DefaultMutex = PTHREAD_MUTEX_INITIALIZER;

  m_Workers = new worker_context_t[m_NumWorkers];
  memset(m_Workers, 0, sizeof(worker_context_t) * m_NumWorkers);
}

CThreadPool::~CThreadPool() { delete[] m_Workers; }

auto CThreadPool::GetNumCPUCores() -> int {
#ifdef _WIN32
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return (int)info.dwNumberOfProcessors;
#else
  return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

auto CThreadPool::RoutineProc(void* _worker) -> void* {
  auto* worker = static_cast<worker_context_t*>(_worker);
  worker->routine(worker->param);
  worker->bRunning = false;
  return nullptr;
}

void CThreadPool::AddWorker(worker_routine_t routine, void* param) {
  while (true) {
    for (int i = 0; i < m_NumWorkers; i++) {
      worker_context_t* worker = &m_Workers[i];

      if (!worker->bRunning) {
        worker->bRunning = true;
        worker->param = param;
        worker->routine = routine;
        pthread_create(&worker->pthread, nullptr, RoutineProc, (void*)worker);
        return;
      }
    }

    usleep(100);
  }
}

void CThreadPool::WaitForWorkers() {
  bool bHaveActiveWorkers = true;

  while (bHaveActiveWorkers) {
    bHaveActiveWorkers = false;

    for (int i = 0; i < m_NumWorkers; i++) {
      if (m_Workers[i].bRunning) {
        bHaveActiveWorkers = true;
      }
    }

    usleep(100);
  }
}

void CThreadPool::LockDefaultMutex() { pthread_mutex_lock(&m_DefaultMutex); }

void CThreadPool::UnlockDefaultMutex() { pthread_mutex_unlock(&m_DefaultMutex); }
