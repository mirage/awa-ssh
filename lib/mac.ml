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
open Rresult.R
open Util

type t =
  | Hmac_md5
  | Hmac_md5_96
  | Hmac_sha1
  | Hmac_sha1_96
  | Hmac_sha2_256
  | Hmac_sha2_512

let to_string = function
  | Hmac_md5      -> "hmac-md5"
  | Hmac_md5_96   -> "hmac-md5-96"
  | Hmac_sha1     -> "hmac-sha1"
  | Hmac_sha1_96  -> "hmac-sha1-96"
  | Hmac_sha2_256 -> "hmac-sha2-256"
  | Hmac_sha2_512 -> "hmac-sha2-512"

let of_string = function
 | "hmac-md5"      -> ok Hmac_md5
 | "hmac-md5-96"   -> ok Hmac_md5_96
 | "hmac-sha1"     -> ok Hmac_sha1
 | "hmac-sha1-96"  -> ok Hmac_sha1_96
 | "hmac-sha2-256" -> ok Hmac_sha2_256
 | "hmac-sha2-512" -> ok Hmac_sha2_512
 | s -> error ("Unknown mac " ^ s)

let known s = is_ok (of_string s)

let preferred = [ Hmac_md5; Hmac_sha1; Hmac_sha2_256;
                  Hmac_sha2_512; Hmac_sha1_96; Hmac_md5_96 ]
