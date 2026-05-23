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

let trap_error f =
  try f () with
  | Invalid_argument e -> Error e
  | Failure e -> Error e

let ( let* ) = Result.bind

let guard p e = if p then Ok () else Error e

let guard_some x e = match x with Some x -> Ok x | None -> Error e

let guard_none x e = match x with None -> Ok () | Some _ -> Error e

let u32_compare a b = (* ignore the sign *)
  let (&&&) x y = Int32.logand x y in
  let (>|>) x y = Int32.shift_right_logical x y in
  let c = Int32.compare (a >|> 1) (b >|> 1) in
  if c = 0 then Int32.compare (a &&& 1l) (b &&& 1l) else c
