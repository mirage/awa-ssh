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

open Digestif

type t =
  | Plaintext
  | Md5
  | Md5_96
  | Sha1
  | Sha1_96
  | Sha2_256
  | Sha2_512

type key = {
  hmac : t;         (* Hmac algorithm *)
  key  : string;    (* The actual hmac key *)
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
 | "none"          -> Ok Plaintext
 | "hmac-md5"      -> Ok Md5
 | "hmac-md5-96"   -> Ok Md5_96
 | "hmac-sha1"     -> Ok Sha1
 | "hmac-sha1-96"  -> Ok Sha1_96
 | "hmac-sha2-256" -> Ok Sha2_256
 | "hmac-sha2-512" -> Ok Sha2_512
 | s -> Error ("Unknown mac " ^ s)

let digest_len = function
  | Plaintext-> 0
  | Md5      -> MD5.digest_size
  | Md5_96   -> 12
  | Sha1     -> SHA1.digest_size
  | Sha1_96  -> 12
  | Sha2_256 -> SHA256.digest_size
  | Sha2_512 -> SHA512.digest_size

let key_len = function
  | Plaintext-> 0
  | Md5      -> MD5.digest_size
  | Md5_96   -> MD5.digest_size
  | Sha1     -> SHA1.digest_size
  | Sha1_96  -> SHA1.digest_size
  | Sha2_256 -> SHA256.digest_size
  | Sha2_512 -> SHA512.digest_size

let known s = Result.is_ok (of_string s)

let preferred = [ Md5; Sha1; Sha2_256;
                  Sha2_512; Sha1_96; Md5_96 ]

let hmacv hmac ~key data =
  let take_96 buf =
    if String.length buf < 12 then
      failwith "digest is too short."
    else
      String.sub buf 0 12
  in
  match hmac with
  | Plaintext -> ""
  | Md5 -> MD5.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string)
  | Md5_96 -> MD5.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string |> take_96)
  | Sha1 -> SHA1.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string)
  | Sha1_96 -> SHA1.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string |> take_96)
  | Sha2_256 -> SHA256.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string)
  | Sha2_512 -> SHA512.(hmaci_string ~key (fun f -> List.iter f data) |> to_raw_string)
