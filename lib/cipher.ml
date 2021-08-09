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
open Mirage_crypto.Cipher_block.AES

type t =
  | Plaintext
  | Aes128_ctr
  | Aes192_ctr
  | Aes256_ctr
  | Aes128_cbc
  | Aes192_cbc
  | Aes256_cbc
  | Chacha20_poly1305

let aead = function
  | Chacha20_poly1305 -> true
  | _ -> false

type cipher_key =
  | Plaintext_key
  | Aes_ctr_key of (CTR.key * CTR.ctr)
  | Aes_cbc_key of (CBC.key * Cstruct.t)
  | Chacha20_poly1305_key of (Mirage_crypto.Chacha20.key * Mirage_crypto.Chacha20.key)

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
  | Chacha20_poly1305 -> "chacha20-poly1305@openssh.com"

let of_string = function
  | "none"       -> ok Plaintext
  | "aes128-ctr" -> ok Aes128_ctr
  | "aes192-ctr" -> ok Aes192_ctr
  | "aes256-ctr" -> ok Aes256_ctr
  | "aes128-cbc" -> ok Aes128_cbc
  | "aes192-cbc" -> ok Aes192_cbc
  | "aes256-cbc" -> ok Aes256_cbc
  | "chacha20-poly1305@openssh.com" -> ok Chacha20_poly1305
  | s -> error ("Unknown cipher " ^ s)

let key_len = function
  | Plaintext  -> 0
  | Aes128_ctr -> 16
  | Aes192_ctr -> 24
  | Aes256_ctr -> 32
  | Aes128_cbc -> 16
  | Aes192_cbc -> 24
  | Aes256_cbc -> 32
  | Chacha20_poly1305 -> 64

let iv_len = function
  | Plaintext -> 0
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size
  | Chacha20_poly1305 -> 0

let block_len = function
  | Plaintext -> 8
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size
  | Chacha20_poly1305 -> 8

let mac_len = function
  | Chacha20_poly1305 -> Mirage_crypto.Poly1305.mac_size
  | _ -> 0

let known s = is_ok (of_string s)

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let enc_dec enc ~len seq cipher buf =
  let open Mirage_crypto.Cipher_block in
  match cipher.cipher_key with
  | Plaintext_key -> ok (buf, cipher)
  | Aes_ctr_key (key, iv) ->
    let f = if enc then AES.CTR.encrypt else AES.CTR.decrypt in
    let buf = f ~key ~ctr:iv buf in
    let next_iv = AES.CTR.next_ctr ~ctr:iv buf in
    let cipher_key = Aes_ctr_key (key, next_iv) in
    let key = { cipher with cipher_key } in
    ok (buf, key)
  | Aes_cbc_key (key, iv) ->
    let f = if enc then AES.CBC.encrypt else AES.CBC.decrypt in
    let buf = f ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    let cipher_key = Aes_cbc_key (key, next_iv) in
    let cipher = { cipher with cipher_key } in
    ok (buf, cipher)
  | Chacha20_poly1305_key (len_key, key) ->
    let nonce =
      let b = Cstruct.create 8 in
      Cstruct.BE.set_uint64 b 0 (Int64.of_int32 seq);
      b
    in
    let c_len b = Mirage_crypto.Chacha20.crypt ~key:len_key ~nonce b in
    let c_data b = Mirage_crypto.Chacha20.crypt ~key ~ctr:1L ~nonce b in
    let mac data =
      let key = Mirage_crypto.Chacha20.crypt ~key ~nonce (Cstruct.create 32) in
      Mirage_crypto.Poly1305.mac ~key data
    in
    if enc then
      let lbuf, msg = Cstruct.split buf 4 in
      let enc_len = c_len lbuf in
      let enc_msg = c_data msg in
      let out = Cstruct.append enc_len enc_msg in
      let tag = mac out in
      ok (Cstruct.append out tag, cipher)
    else
      begin
        if len then
          ok (c_len buf, cipher)
        else
          let c, tag =
            let off = Cstruct.length buf - Mirage_crypto.Poly1305.mac_size in
            Cstruct.split buf off
          in
          let ctag = mac c in
          let enc_len, enc_msg = Cstruct.split c 4 in
          let dec_len = c_len enc_len
          and dec_msg = c_data enc_msg
          in
          if Cstruct.equal ctag tag then
            ok (Cstruct.append dec_len dec_msg, cipher)
          else
            error "tag verification failed"
      end

let encrypt ~len seq cipher buf =
  match enc_dec true ~len seq cipher buf with
  | Ok a -> a
  | Error _ -> assert false
let decrypt = enc_dec false

let preferred = [ Chacha20_poly1305 ;
                  Aes128_ctr; Aes192_ctr; Aes256_ctr;
                  Aes128_cbc; Aes192_cbc; Aes256_cbc; ]
