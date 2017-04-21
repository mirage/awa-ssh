(*
 * Copyright (c) 2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

type t = {
  tlen : int;
  coff : int;
  cbuf : Cstruct.t;
}

let chunk_size = 1024

let create () =
  { tlen = chunk_size; coff = 0; cbuf = Cstruct.create chunk_size }

let to_cstruct t = Cstruct.set_len t.cbuf t.coff

let left t = t.tlen - t.coff

let used t = t.coff

let grow len t =
  let tlen = t.tlen + len in
  let cbuf = Cstruct.append t.cbuf (Cstruct.create len) in
  { t with tlen; cbuf }

let guard_space len t =
  if (left t) >= len then t else grow (max len chunk_size) t

let shift n t = { t with coff = t.coff + n }

let reserve n t = shift n t

let put_uint8 b t =
  let t = guard_space 1 t in
  Cstruct.set_uint8 t.cbuf t.coff b;
  shift 1 t

let put_uint32_be w t =
  let t = guard_space 4 t in
  Cstruct.BE.set_uint32 t.cbuf t.coff w;
  shift 4 t

