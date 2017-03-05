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
open Nocrypto.Hash

type t =
  | Plaintext
  | Md5
  | Md5_96
  | Sha1
  | Sha1_96
  | Sha2_256
  | Sha2_512

type key = {
  hmac : t;            (* Hmac algorithm *)
  key  : Cstruct.t;    (* The actual hmac key *)
  seq  : int32;        (* Sequence number for hmac *)
}

let to_string = function
  | Plaintext-> "none"
  | Md5      -> "hmac-md5"
  | Md5_96   -> "hmac-md5-96"
  | Sha1     -> "hmac-sha1"
  | Sha1_96  -> "hmac-sha1-96"
  | Sha2_256 -> "hmac-sha2-256"
  | Sha2_512 -> "hmac-sha2-512"

let of_string = function
 | "none"          -> ok Plaintext
 | "hmac-md5"      -> ok Md5
 | "hmac-md5-96"   -> ok Md5_96
 | "hmac-sha1"     -> ok Sha1
 | "hmac-sha1-96"  -> ok Sha1_96
 | "hmac-sha2-256" -> ok Sha2_256
 | "hmac-sha2-512" -> ok Sha2_512
 | s -> error ("Unknown mac " ^ s)

let digest_len = function
  | Plaintext-> 0
  | Md5      -> MD5.digest_size
  | Md5_96   -> 12
  | Sha1     -> SHA1.digest_size
  | Sha1_96  -> 12
  | Sha2_256 -> SHA256.digest_size
  | Sha2_512 -> SHA512.digest_size

let known s = is_ok (of_string s)

let preferred = [ Md5; Sha1; Sha2_256;
                  Sha2_512; Sha1_96; Md5_96 ]
