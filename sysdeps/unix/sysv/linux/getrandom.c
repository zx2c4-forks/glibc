/* Implementation of the getrandom system call.
   Copyright (C) 2016-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <libc-lock.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sysdep-cancel.h>
#include <ldsodefs.h>
#include <tls-internal.h>

#ifdef __NR_vgetrandom_alloc

static struct
{
  __libc_lock_define (, lock);
  void **states;
  size_t len;
  size_t cap;
} grnd_allocator =
{
  .lock = LLL_LOCK_INITIALIZER
};

static void *
vgetrandom_alloc_syscall (unsigned int *num, unsigned int *size_per_each,
                          unsigned int flags)
{
  long int r = INTERNAL_SYSCALL_CALL (vgetrandom_alloc, num, size_per_each, 0);
  return INTERNAL_SYSCALL_ERROR_P(r) ? NULL : (void *) r;
}

static struct grnd_allocator_state *
vgetrandom_get_state (void)
{
  void *state = NULL;

  __libc_lock_lock (grnd_allocator.lock);

  if (grnd_allocator.len == 0)
    {
      size_t new_cap;
      unsigned int size_per_each;
      unsigned int num = 16; /* Could make nr_cpus. */

      void *new_block = vgetrandom_alloc_syscall (&num, &size_per_each, 0);
      if (new_block == NULL)
        goto out;

      new_cap = grnd_allocator.cap + num;
      void *new_states = __libc_reallocarray (grnd_allocator.states, new_cap,
        sizeof (*grnd_allocator.states));
      if (new_states == NULL)
        {
          __munmap (new_block, num * size_per_each);
          goto out;
        }

      grnd_allocator.cap = new_cap;
      grnd_allocator.states = new_states;

      for (size_t i = 0; i < num; ++i)
        {
          grnd_allocator.states[i] = new_block;
          new_block += size_per_each;
        }
      grnd_allocator.len = num;
    }

  state = grnd_allocator.states[--grnd_allocator.len];

out:
  __libc_lock_unlock (grnd_allocator.lock);
  return state;
}

/* Return true if the syscall fallback should be issued in the case the vDSO
   is not present or if any memory allocation fails.  */
static bool
__getrandom_internal (ssize_t *ret, void *buffer, size_t length,
                      unsigned int flags)
{
  if (GLRO(dl_vdso_getrandom) == NULL)
    return false;

  struct tls_internal_t *ti = __glibc_tls_internal ();
  void *state = ti->getrandom_buf;

  if (state == NULL)
    {
      state = vgetrandom_get_state ();
      if (state == NULL)
        return false;
      ti->getrandom_buf = state;
    }

  *ret = GLRO(dl_vdso_getrandom)(buffer, length, flags, state);
  if (INTERNAL_SYSCALL_ERROR_P (*ret))
    {
      __set_errno (INTERNAL_SYSCALL_ERRNO (*ret));
      *ret = -1;
    }
  return true;
}
#endif

ssize_t
__getrandom_nocancel (void *buffer, size_t length, unsigned int flags)
{
#ifdef __NR_vgetrandom_alloc
  ssize_t r;
  if (__getrandom_internal (&r, buffer, length, flags))
    return r;
#endif

  return SYSCALL_CANCEL (getrandom, buffer, length, flags);
}

/* Write up to LENGTH bytes of randomness starting at BUFFER.
   Return the number of bytes written, or -1 on error.  */
ssize_t
__getrandom (void *buffer, size_t length, unsigned int flags)
{
#ifdef __NR_vgetrandom_alloc
  ssize_t r;
  if (__getrandom_internal (&r, buffer, length, flags))
    return r;
#endif

  return INTERNAL_SYSCALL_CALL (getrandom, buffer, length, flags);
}
libc_hidden_def (__getrandom)
weak_alias (__getrandom, getrandom)

void
__getrandom_vdso_release (void)
{
#ifdef __NR_vgetrandom_alloc
  void *state = __glibc_tls_internal ()->getrandom_buf;
  if (state == NULL)
    return;

  __libc_lock_lock (grnd_allocator.lock);
  grnd_allocator.states[grnd_allocator.len++] = state;
  __libc_lock_unlock (grnd_allocator.lock);
#endif
}
