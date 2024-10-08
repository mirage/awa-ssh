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

open Mirage_crypto

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
  | Aes_ctr_key of (AES.CTR.key * AES.CTR.ctr)
  | Aes_cbc_key of (AES.CBC.key * string)
  | Chacha20_poly1305_key of (Chacha20.key * Chacha20.key)

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
  | "none"       -> Ok Plaintext
  | "aes128-ctr" -> Ok Aes128_ctr
  | "aes192-ctr" -> Ok Aes192_ctr
  | "aes256-ctr" -> Ok Aes256_ctr
  | "aes128-cbc" -> Ok Aes128_cbc
  | "aes192-cbc" -> Ok Aes192_cbc
  | "aes256-cbc" -> Ok Aes256_cbc
  | "chacha20-poly1305@openssh.com" -> Ok Chacha20_poly1305
  | s -> Error ("Unknown cipher " ^ s)

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
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> AES.CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> AES.CBC.block_size
  | Chacha20_poly1305 -> 0

let block_len = function
  | Plaintext -> 8
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> AES.CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> AES.CBC.block_size
  | Chacha20_poly1305 -> 8

let mac_len = function
  | Chacha20_poly1305 -> Poly1305.mac_size
  | _ -> 0

let known s = Result.is_ok (of_string s)

(* For some reason mirage-crypto CTR modifies ctr in place, CBC returns next *)
let enc_dec enc ~len seq cipher buf =
  match cipher.cipher_key with
  | Plaintext_key -> Ok (buf, cipher)
  | Aes_ctr_key (key, iv) ->
    let f = if enc then AES.CTR.encrypt else AES.CTR.decrypt in
    let buf = f ~key ~ctr:iv buf in
    let next_iv = AES.CTR.next_ctr ~ctr:iv buf in
    let cipher_key = Aes_ctr_key (key, next_iv) in
    let key = { cipher with cipher_key } in
    Ok (buf, key)
  | Aes_cbc_key (key, iv) ->
    let f = if enc then AES.CBC.encrypt else AES.CBC.decrypt in
    let buf = f ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    let cipher_key = Aes_cbc_key (key, next_iv) in
    let cipher = { cipher with cipher_key } in
    Ok (buf, cipher)
  | Chacha20_poly1305_key (len_key, key) ->
    let nonce =
      let b = Bytes.create 8 in
      Bytes.set_int64_be b 0 (Int64.of_int32 seq);
      Bytes.unsafe_to_string b
    in
    let c_len b = Chacha20.crypt ~key:len_key ~nonce b in
    let c_data b = Chacha20.crypt ~key ~ctr:1L ~nonce b in
    let mac data =
      let key = Chacha20.crypt ~key ~nonce (String.make 32 '\000') in
      Poly1305.mac ~key data
    in
    if enc then
      let lbuf, msg = String.sub buf 0 4, String.sub buf 4 (String.length buf - 4) in
      let enc_len = c_len lbuf in
      let enc_msg = c_data msg in
      let out = enc_len ^ enc_msg in
      let tag = mac out in
      Ok (out ^ tag, cipher)
    else
      begin
        if len then
          Ok (c_len buf, cipher)
        else
          let c, tag =
            let off = String.length buf - Poly1305.mac_size in
            String.sub buf 0 off, String.sub buf off (String.length buf - off)
          in
          let ctag = mac c in
          let enc_len, enc_msg = String.sub c 0 4, String.sub c 4 (String.length c - 4) in
          let dec_len = c_len enc_len
          and dec_msg = c_data enc_msg
          in
          if String.equal ctag tag then
            Ok (dec_len ^ dec_msg, cipher)
          else
            Error "tag verification failed"
      end

let encrypt ~len seq cipher buf =
  match enc_dec true ~len seq cipher buf with
  | Ok a -> a
  | Error _ -> assert false
let decrypt = enc_dec false

let preferred = [ Chacha20_poly1305 ;
                  Aes128_ctr; Aes192_ctr; Aes256_ctr;
                  Aes128_cbc; Aes192_cbc; Aes256_cbc; ]
