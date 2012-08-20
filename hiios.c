/* hiios.c  -  Hiquu I/O Engine I/O shuffler
 * Copyright (c) 2006,2012 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
 * This is confidential unpublished proprietary source code of the author.
 * NO WARRANTY, not even implied warranties. Contains trade secrets.
 * Distribution prohibited unless authorized in writing. See file COPYING.
 * Special grant: hiios.c may be used with zxid open source project under
 * same licensing terms as zxid itself.
 * $Id$
 *
 * 15.4.2006, created over Easter holiday --Sampo
 * 16.8.2012, modified license grant to allow use with ZXID.org --Sampo
 *
 * See http://pl.atyp.us/content/tech/servers.html for inspiration on threading strategy.
 *
 *   MANY ELEMENTS IN QUEUE            ONE ELEMENT IN Q   EMPTY QUEUE
 *   consume             produce       consume  produce   consume  produce
 *    |                   |             | ,-------'         |        |
 *    V                   V             V V                 V        V
 *   qel.n --> qel.n --> qel.n --> 0   qel.n --> 0          0        0
 */

#ifdef LINUX
#include <sys/epoll.h>     /* See man 4 epoll (Linux 2.6) */
#endif
#ifdef SUNOS
#include <sys/devpoll.h>   /* See man -s 7d poll (Solaris 8) */
#include <sys/poll.h>
#endif

#include <pthread.h>
#include <malloc.h>
#include <memory.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

#include "akbox.h"
#include "hiproto.h"
#include "hiios.h"
#include "errmac.h"

/*() Allocate io structure (connection) pool and global PDU
 * pool, from which per thread pools will be plensihed - see
 * hi_pdu_alloc() - and initialize syncronization primitives. */

/* Called by:  main */
struct hiios* hi_new_shuffler(int nfd, int npdu)
{
  int i;
  struct hiios* shf;
  ZMALLOC(shf);
  ZMALLOCN(shf->ios, sizeof(struct hi_io)*nfd);
  shf->max_ios = nfd;
  for (i = 0; i < nfd; ++i) {
    pthread_mutex_init(&shf->ios[i].qel.mut, MUTEXATTR);
  }
  
  /* Allocate global pool of PDUs (as a blob) */
  ZMALLOCN(shf->pdu_buf_blob, sizeof(struct hi_pdu)*npdu);
  shf->max_pdus = npdu;
  for (i = npdu - 1; i; --i) {  /* Link the PDUs to a list. */
    shf->pdu_buf_blob[i-1].qel.n = (struct hi_qel*)(shf->pdu_buf_blob + i);
    pthread_mutex_init(&shf->pdu_buf_blob[i].qel.mut, MUTEXATTR);
  }
  pthread_mutex_init(&shf->pdu_buf_blob[0].qel.mut, MUTEXATTR);
  shf->free_pdus = shf->pdu_buf_blob;  /* Make PDUs available as free. */
  pthread_mutex_init(&shf->pdu_mut, MUTEXATTR);
  
  pthread_cond_init(&shf->todo_cond, 0);
  pthread_mutex_init(&shf->todo_mut, MUTEXATTR);

  shf->poll_tok.kind = HI_POLL;           /* Permanently labeled as poll_tok (there is only 1) */
  shf->poll_tok.proto = HIPROTO_POLL_ON;  /* token is available */

  shf->max_evs = MIN(nfd, 1024);
#ifdef LINUX
  shf->ep = epoll_create(nfd);
  if (shf->ep == -1) { perror("epoll"); exit(1); }
  ZMALLOCN(shf->evs, sizeof(struct epoll_event) * shf->max_evs);
#endif
#ifdef SUNOS
  shf->ep = open("/dev/poll", O_RDWR);
  if (shf->ep == -1) { perror("open(/dev/poll)"); exit(1); }
  ZMALLOCN(shf->evs, sizeof(struct pollfd) * shf->max_evs);
#endif
  return shf;
}

/*() Set socket to be nonblocking.
 * Our I/O strategy (edge triggered epoll or /dev/poll) depends on nonblocking fds. */

/* Called by:  hi_accept, hi_open_listener, hi_open_tcp, serial_init, zxbus_open_bus_url */
void nonblock(int fd)
{
#ifdef MINGW
  u_long arg = 1;
  if (ioctlsocket(fd, FIONBIO, &arg) == SOCKET_ERROR) {
    ERR("Unable to ioctlsocket(%d, FIONBIO, 1): %d %s", fd, errno, STRERROR(errno));
    exit(2);
  }
#else
#if 0
  int fflags = fcntl(fd, F_GETFL, 0);
  if (fflags == -1) {
    ERR("Unable to fcntl(F_GETFL) on socket %d: %d %s", fd, errno, STRERROR(errno));
    exit(2);
  }
  fflags |= O_NONBLOCK | O_NDELAY;  /* O_ASYNC would be synonymous */
#endif

  if( fcntl(fd, F_SETFL, O_NONBLOCK | O_NDELAY) == -1) {
    ERR("Unable to fcntl(F_SETFL) on socket %d: %d %s", fd, errno, STRERROR(errno));
    exit(2);
  }

#if 0
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
    ERR("fcntl(F_SETFD,FD_CLOEXEC) system call failed for %d: %d %s", fd, errno, STRERROR(errno));
    exit(2);
  }
#endif
#endif
}

/* Tweaking kernel buffers to be smaller can be a win if a massive number
 * of connections are simultaneously open. On many systems default buffer
 * size is 64KB in each direction, leading to 128KB memory consumption. Tweaking
 * to only, say, 8KB can bring substantial savings (but may hurt TCP performance). */

/* Called by:  hi_accept, hi_open_listener, hi_open_tcp, zxbus_open_bus_url */
void setkernelbufsizes(int fd, int tx, int rx)
{
  /* See `man 7 tcp' for TCP_CORK, TCP_NODELAY, etc. */
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&tx, sizeof(tx)) == -1) {
    ERR("setsockopt(SO_SNDBUF, %d) on fd=%d: %d %s", tx, fd, errno, STRERROR(errno));
    exit(2);
  }
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&rx, sizeof(rx)) == -1) {
    ERR("setsockopt(SO_RCVBUF, %d) on fd=%d: %d %s", rx, fd, errno, STRERROR(errno));
    exit(2);
  }
}

extern int nkbuf;
extern int listen_backlog;

/* Called by:  main */
struct hi_io* hi_open_listener(struct hiios* shf, struct hi_host_spec* hs, int proto)
{
  struct hi_io* io;
  int fd, tmp;
  if ((fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
    ERR("Unable to create socket(AF_INET, SOCK_STREAM, 0) %d %s", errno, STRERROR(errno));
    return 0;
  }
  nonblock(fd);
  if (nkbuf)
    setkernelbufsizes(fd, nkbuf, nkbuf);

  tmp = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof(tmp)) == -1) {
    ERR("Failed to call setsockopt(REUSEADDR) on %d: %d %s", fd, errno, STRERROR(errno));
    exit(2);
  }

  if (bind(fd, (struct sockaddr*)&hs->sin, sizeof(struct sockaddr_in))) {
    ERR("Unable to bind socket %d (%s): %d %s (trying again in 2 secs)",
	fd, hs->specstr, errno, STRERROR(errno));
    /* It appears to be a problem under 2.5.7x series kernels that if you kill a process that
     * was listening to a port, you can not immediately bind on that same port again. */
    sleep(2);
    if (bind (fd, (struct sockaddr*)&hs->sin, sizeof(struct sockaddr_in))) {
      ERR("Unable to bind socket %d (%s): %d %s (giving up)",
	  fd, hs->specstr, errno, STRERROR(errno));
      close(fd);
      return 0;
    }
  }
  
  if (listen(fd, listen_backlog)) {
    ERR("Unable to listen(%d, %d) (%s): %d %s",
	fd, listen_backlog, hs->specstr, errno, STRERROR(errno));
    close(fd);
    return 0;
  }

  io = shf->ios + fd;

#ifdef LINUX
  {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;  /* ET == EdgeTriggered */
    ev.data.ptr = io;
    if (epoll_ctl(shf->ep, EPOLL_CTL_ADD, fd, &ev)) {
      ERR("Unable to epoll_ctl(%d) (%s): %d %s", fd, hs->specstr, errno, STRERROR(errno));
      close(fd);
      return 0;
    }
  }
#endif
#ifdef SUNOS
  {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR;
    if (write(shf->ep, &pfd, sizeof(pfd)) == -1) {
      ERR("Unable to write to /dev/poll fd(%d) (%s): %d %s", fd, hs->specstr, errno, STRERROR(errno));
      close(fd);
      return 0;
    }
  }
#endif

  io->fd = fd;
  io->qel.kind = HI_LISTEN;
  io->qel.proto = proto;
  io->description = hs->specstr;
  D("listen(%x) hs(%s)", fd, hs->specstr);
  return io;
}

/*() Add file descriptor to poll */

/* Called by:  hi_accept, hi_open_tcp, serial_init */
struct hi_io* hi_add_fd(struct hiios* shf, int fd, int proto, int kind, char *desc)
{
  struct hi_io* io = shf->ios + fd;  /* uniqueness of fd acts as mutual exclusion mechanism */

#ifdef LINUX
  {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET;  /* ET == EdgeTriggered */
    ev.data.ptr = io;
    if (epoll_ctl(shf->ep, EPOLL_CTL_ADD, fd, &ev)) {
      ERR("Unable to epoll_ctl(%d): %d %s", fd, errno, STRERROR(errno));
      close(fd);
      return 0;
    }
  }
#endif
#ifdef SUNOS
  {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT | POLLERR | POLLHUP;
    if (write(shf->ep, &pfd, sizeof(pfd)) == -1) {
      ERR("Unable to write to /dev/poll fd(%d): %d %s", fd, errno, STRERROR(errno));
      close(fd);
      return 0;
    }
  }
#endif

  memset(io, 0, sizeof(struct hi_io));
  io->fd = fd;
  io->qel.kind = kind;
  io->qel.proto = proto;
  io->description = desc;
  return io;
}

/*() Create client socket. */

/* Called by:  main, smtp_send */
struct hi_io* hi_open_tcp(struct hiios* shf, struct hi_host_spec* hs, int proto)
{
  int fd;
  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    ERR("Unable to create socket(AF_INET, SOCK_STREAM, 0) %d %s", errno, STRERROR(errno));
    return 0;
  }

  nonblock(fd);
  if (nkbuf)
    setkernelbufsizes(fd, nkbuf, nkbuf);
  
  if ((connect(fd, (struct sockaddr*)&hs->sin, sizeof(hs->sin)) == -1)
      && (errno != EINPROGRESS)) {
    int myerrno = errno;
    close(fd);
    ERR("Connection to %s failed: %d %s", hs->specstr, myerrno, STRERROR(myerrno));
    return 0;
  }
  
  D("connect(%x) hs(%s)", fd, hs->specstr);
  return hi_add_fd(shf, fd, proto, HI_TCP_C, hs->specstr);
}

/*() Create server side worker socket by accept(2)ing from listener socket. */

/* Called by:  hi_shuffle */
static void hi_accept(struct hi_thr* hit, struct hi_io* listener)
{
  //struct hi_host_spec* hs;
  struct hi_io* io;
  struct sockaddr_in sa;
  int fd;
  size_t size;
  size = sizeof(sa);
  if ((fd = accept(listener->fd, (struct sockaddr*)&sa, &size)) == -1) {
    if (errno != EAGAIN)
      ERR("Unable to accept from %d: %d %s", listener->fd, errno, STRERROR(errno));
    return;
  }
  nonblock(fd);
  if (nkbuf)
    setkernelbufsizes(fd, nkbuf, nkbuf);
  io = hi_add_fd(hit->shf, fd, listener->qel.proto, HI_TCP_S, listener->description);
  D("accept(%x) from(%x)", fd, listener->fd);
  ++listener->n_read;  /* n_read counter is used for accounting accepts */
  
  switch (listener->qel.proto) {
  case HIPROTO_SMTP: /* In SMTP, server starts speaking first */
    hi_sendf(hit, io, 0, "220 %s smtp ready\r\n", SMTP_GREET_DOMAIN);
    io->ad.smtp.state = SMTP_START;
    break;
#ifdef ENA_S5066
  case HIPROTO_DTS:
    ZMALLOC(io->ad.dts);
    io->ad.dts->remote_station_addr[0] = 0x61;   /* three nibbles long (padded with zeroes) */
    io->ad.dts->remote_station_addr[1] = 0x45;
    io->ad.dts->remote_station_addr[2] = 0x00;
    io->ad.dts->remote_station_addr[3] = 0x00;
    if (!(hs = prototab[HIPROTO_DTS].specs)) {
      ZMALLOC(hs);
      hs->proto = HIPROTO_DTS;
      hs->specstr = "dts:accepted:connections";
      hs->next = prototab[HIPROTO_DTS].specs;
      prototab[HIPROTO_DTS].specs = hs;
    }
    io->n = hs->conns;
    hs->conns = io;
    break;
#endif
  }
  
  hi_todo_produce(hit->shf, &listener->qel);  /* Must exhaust accept: reenqueue (could also loop). */
}

/*() Close an I/O object.
 * This involves special cleanup of todo queue. */

/* Called by:  hi_in_out, hi_read x3, hi_write */
void hi_close(struct hi_thr* hit, struct hi_io* io)
{
  struct hi_pdu* pdu;
  int fd = io->fd;
  D("close(%x)", fd);
#if 0  /* should never happen because io had to be consumed before hi_in_out() was called. */
  LOCK(hit->shf->todo_mut, "hi_close");
  if (io->qel.intodo) {
    if (hit->shf->todo_consume == &io->qel) {
      hi_todo_consume_inlock(hit->shf);
    } else {  /* Tricky consume from middle of queue. O(n) to queue size :-( */
      /* Since io->intodo is set, io must be in the queue. If it's not, following loop
       * will crash with NULL next pointer in the end. Or be infinite loop if a
       * loop of next pointers was somehow created. Both are programming errors. */
      for (qe = hit->shf->todo_consume; 1; qe = qe->n)
	if (qe->n == &io->qel) {
	  qe->n = io->qel.n;
	  break; /* only way out */
	}
      if (!qe->n)
	hit->shf->todo_produce = qe;
      qe->n = 0;
      qe->intodo = 0;
      --hit->shf->n_todo;
    }
  }
  UNLOCK(hit->shf->todo_mut, "hi_close");
#else
  ASSERT(!io->qel.intodo);
#endif
  /* *** deal with freeing associated PDUs. If fail, consider shutdown(2) of socket
   *     and reenqueue to todo list so freeing can be tried again later. */
  
  for (pdu = io->reqs; pdu; pdu = pdu->n)
    hi_free_req(hit, pdu);
  
  if (io->cur_pdu) {
    hi_free_req(hit, io->cur_pdu);
    io->cur_pdu = 0;
  }
#ifdef ENA_S5066
  void sis_clean(struct hi_io* io);
  sis_clean(io);
#endif

  io->fd |= 0x80000000;  /* mark as free */
  close(fd);             /* now some other thread may reuse the slot by accept()ing same fd */
  D("closed(%x)", fd);
}

/* -------- todo_queue management, waking up threads to consume work (io, pdu) -------- */

/*() Simple mechanics of deque operation against shf->todo_consumer */

/* Called by:  hi_close, hi_todo_consume */
static struct hi_qel* hi_todo_consume_inlock(struct hiios* shf)
{
  struct hi_qel* qe = shf->todo_consume;
  shf->todo_consume = qe->n;
  if (!qe->n)
    shf->todo_produce = 0;
  qe->n = 0;
  qe->intodo = 0;
  --shf->n_todo;
  return qe;
}

/*(i) Consume from todo queue. If nothing is available,
 * block until there is work to do. This is the main
 * mechanism by which worker threads get something to do. */

/* Called by:  hi_shuffle */
static struct hi_qel* hi_todo_consume(struct hiios* shf)
{
  struct hi_qel* qe;
  LOCK(shf->todo_mut, "todo_con");
  while (!shf->todo_consume && !shf->poll_tok.proto)    /* Empty todo queue? */
    pthread_cond_wait(&shf->todo_cond, &shf->todo_mut); /* Block until there is work. */
  if (shf->todo_consume)
    qe = hi_todo_consume_inlock(shf);
  else {
    ASSERT(shf->poll_tok.proto);
    shf->poll_tok.proto = HIPROTO_POLL_OFF;
    qe = &shf->poll_tok;
  }
  UNLOCK(shf->todo_mut, "todo_con");
  return qe;
}

/*(i) Schedule new work to be done, potentially waking up the consumer threads! */

/* Called by:  hi_accept, hi_poll x2, hi_read */
void hi_todo_produce(struct hiios* shf, struct hi_qel* qe)
{
  LOCK(shf->todo_mut, "todo_prod");
  if (!qe->intodo) {
    if (shf->todo_produce)
      shf->todo_produce->n = qe;
    else
      shf->todo_consume = qe;
    shf->todo_produce = qe;
    qe->n = 0;
    qe->intodo = 1;
    ++shf->n_todo;
    pthread_cond_signal(&shf->todo_cond);  /* Wake up consumers */
  }
  UNLOCK(shf->todo_mut, "todo_prod");
}

/* ---------- shuffler ---------- */

extern int debugpoll;
#define DP(format,...) (debugpoll && (fprintf(stderr, "t%x %9s:%-3d %-16s p " format "\n", (int)pthread_self(), __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__), fflush(stderr)))

/* Called by:  hi_shuffle */
static void hi_poll(struct hiios* shf)
{
  struct hi_io* io;
  int i;
  DP("epoll(%x)", shf->ep);
#ifdef LINUX
  shf->n_evs = epoll_wait(shf->ep, shf->evs, shf->max_evs, -1);
  if (shf->n_evs == -1) {
    ERR("epoll_wait(%x): %d %s", shf->ep, errno, STRERROR(errno));
    return;
  }
  for (i = 0; i < shf->n_evs; ++i) {
    io = (struct hi_io*)shf->evs[i].data.ptr;
    io->events = shf->evs[i].events;
    /* Poll says work is possible: sched wk for io if not under wk yet, or cur_pdu needs wk.
     * The inverse is also important: if io->cur_pdu is set, but need is not, then someone
     * is alredy working on decoding the cur_pdu and we should not interfere.
     * *** How can we allow writes to be done by different thread, while cur_pdu
     * *** processing is happening? Currently ignoring this problem as writes are usually
     * *** desired (for response or subreq) once pdu has been decoded and cur_pdu unset. */
    if (!io->cur_pdu || io->cur_pdu->need)
      hi_todo_produce(shf, &io->qel);  /* *** should the todo_mut lock be batched instead? */
  }
#endif
#ifdef SUNOS
  {
    struct dvpoll dp;
    dp.dp_timeout = -1;
    dp.dp_nfds = shf->max_evs;
    dp.dp_fds = shf->evs;
    shf->n_evs = ioctl(shf->ep, DP_POLL, &dp);
    if (shf->n_evs < 0) {
      ERR("/dev/poll ioctl(%x): %d %s", shf->ep, errno, STRERROR(errno));
      return;
    }
    for (i = 0; i < shf->n_evs; ++i) {
      io = shf->ios + shf->evs[i].fd;
      io->events = shf->evs[i].revents;
      /* Poll says work is possible: sched wk for io if not under wk yet, or cur_pdu needs wk. */
      if (!io->cur_pdu || io->cur_pdu->need)
	hi_todo_produce(shf, &io->qel);  /* *** should the todo_mut lock be batched instead? */
    }
  }
#endif
  LOCK(shf->todo_mut, "todo_prod");
  shf->poll_tok.proto = HIPROTO_POLL_ON;  /* special "on" flag - not a real protocol */
  UNLOCK(shf->todo_mut, "todo_prod");
}

/* Called by:  hi_shuffle */
void hi_process(struct hi_thr* hit, struct hi_pdu* pdu)
{
  D("pdu(%x) events=0x%x", pdu->op, pdu->events);
  /* *** process "continuing" event on a PDU */
}

/* Called by:  hi_shuffle */
void hi_in_out(struct hi_thr* hit, struct hi_io* io)
{
  DP("in_out(%x) events=0x%x", io->fd, io->events);
#ifdef SUNOS
#define EPOLLHUP (POLLHUP)
#define EPOLLERR (POLLERR)
#define EPOLLOUT (POLLOUT)
#define EPOLLIN  (POLLIN)
#endif
  if (io->events & (EPOLLHUP | EPOLLERR)) {
    D("HUP or ERR on fd=%x events=0x%x", io->fd, io->events);
    hi_close(hit, io);
    return;
  }
  
  if (io->events & EPOLLOUT) {
    DP("OUT fd=%x n_iov=%d n_to_write=%d", io->fd, io->n_iov, io->n_to_write);
    hi_write(hit, io);
  }
  
  if (io->events & EPOLLIN) {
    DP("IN fd=%x", io->fd);
    hi_read(hit, io);
  }
}

/*() Main I/O shuffling loop. Never returns. Main loop of most (all?) threads. */

/* Called by:  main, thread_loop */
void hi_shuffle(struct hi_thr* hit, struct hiios* shf)
{
  struct hi_qel* qe;
  hit->shf = shf;
  while (1) {
    HI_SANITY(hit->shf, hit);
    qe = hi_todo_consume(shf);  /* Wakes up the heard to receive work. */
    switch (qe->kind) {
    case HI_POLL:    hi_poll(shf); break;
    case HI_LISTEN:  hi_accept(hit, (struct hi_io*)qe); break;
    case HI_TCP_C:
    case HI_TCP_S:   hi_in_out(hit, (struct hi_io*)qe); break;
    case HI_PDU:     hi_process(hit, (struct hi_pdu*)qe); break;
#ifdef HAVE_NET_SNMP
    case HI_SNMP:    if (snmp_port) processSNMP(); break; /* *** needs more thought */
#endif
    default: NEVER("unknown qel->kind 0x%x", qe->kind);
    }
  }
}

/* EOF  --  hiios.c */
