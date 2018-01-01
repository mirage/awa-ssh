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

open Rresult.R
open Nocrypto.Cipher_block.AES

type t =
  | Plaintext
  | Aes128_ctr
  | Aes192_ctr
  | Aes256_ctr
  | Aes128_cbc
  | Aes192_cbc
  | Aes256_cbc

type cipher_key =
  | Plaintext_key
  | Aes_ctr_key of (CTR.key * Nocrypto.Cipher_block.Counters.C128be.t)
  | Aes_cbc_key of (CBC.key * Cstruct.t)

type key = {
  cipher     : t;
  cipher_key : cipher_key;
}

let to_string = function
  | Plaintext   -> "none"
  | Aes128_ctr -> "aes128-ctr"
  | Aes192_ctr -> "aes192-ctr"
  | Aes256_ctr -> "aes256-ctr"
  | Aes128_cbc -> "aes128-cbc"
  | Aes192_cbc -> "aes192-cbc"
  | Aes256_cbc -> "aes256-cbc"

let of_string = function
  | "none"       -> ok Plaintext
  | "aes128-ctr" -> ok Aes128_ctr
  | "aes192-ctr" -> ok Aes192_ctr
  | "aes256-ctr" -> ok Aes256_ctr
  | "aes128-cbc" -> ok Aes128_cbc
  | "aes192-cbc" -> ok Aes192_cbc
  | "aes256-cbc" -> ok Aes256_cbc
  | s -> error ("Unknown cipher " ^ s)

let key_len = function
  | Plaintext  -> 0
  | Aes128_ctr -> 16
  | Aes192_ctr -> 24
  | Aes256_ctr -> 32
  | Aes128_cbc -> 16
  | Aes192_cbc -> 24
  | Aes256_cbc -> 32

let iv_len = function
  | Plaintext -> 0
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size

let block_len = function
  | Plaintext -> 8
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size

let known s = is_ok (of_string s)

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let enc_dec enc cipher buf =
  let open Nocrypto.Cipher_block in
  match cipher.cipher_key with
  | Plaintext_key -> buf, cipher
  | Aes_ctr_key (key, iv) ->
    let f = if enc then AES.CTR.encrypt else AES.CTR.decrypt in
    let buf = f ~key ~ctr:iv buf in
    let next_iv = AES.CTR.next_ctr ~ctr:iv buf in
    let cipher_key = Aes_ctr_key (key, next_iv) in
    let key = { cipher with cipher_key } in
    buf, key
  | Aes_cbc_key (key, iv) ->
    let f = if enc then AES.CBC.encrypt else AES.CBC.decrypt in
    let buf = f ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    let cipher_key = Aes_cbc_key (key, next_iv) in
    let cipher = { cipher with cipher_key } in
    buf, cipher

let encrypt = enc_dec true
let decrypt = enc_dec false

let preferred = [ Aes128_ctr; Aes192_ctr; Aes256_ctr;
                  Aes128_cbc; Aes192_cbc; Aes256_cbc; ]
