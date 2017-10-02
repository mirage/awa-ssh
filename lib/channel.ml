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

open Sexplib.Conv

type channel_end = {
  id       : int32;
  win      : int32;
  max_pkt  : int32;
} [@@deriving sexp]

type channel = {
  us   : channel_end;
  them : channel_end;
} [@@deriving sexp]

let compare a b =
  Int32.compare a.us.id b.us.id

type t = channel

module Ordered = struct
  type t = channel
  let compare = compare
end

let make_end id win max_pkt =
  { id; win; max_pkt }

let make ~us ~them = { us; them }

let to_string t = Sexplib.Sexp.to_string_hum (sexp_of_channel t)
