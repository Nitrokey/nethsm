/* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*/

#include <stdint.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>

/* Declared here instead of including solo5.h so that this file also compiles
   in the unix context, where it is never referenced. */
extern uint64_t solo5_clock_wall(void);

/* Native version: the unboxed external in raw_clock.ml expects a raw int64_t
   and never allocates. */
int64_t keyfender_clock_wall_native(value unit)
{
  (void)unit;
  return (int64_t)solo5_clock_wall();
}

/* Bytecode version: boxed result. */
value keyfender_clock_wall_byte(value unit)
{
  (void)unit;
  return caml_copy_int64(solo5_clock_wall());
}
