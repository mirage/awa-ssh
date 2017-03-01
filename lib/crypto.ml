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

let hmac hkey seq buf =
  let open Hmac in
  let open Nocrypto.Hash in
  let hmac = fst hkey in
  let key = snd hkey in
  let seqbuf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 seqbuf 0 seq;
  let take_96 buf =
    if (Cstruct.len buf) < 12 then
      failwith "digest is too short."
    else
      Cstruct.set_len buf 12
  in
  match hmac with
  | Md5 -> MD5.hmacv ~key [ seqbuf; buf ]
  | Md5_96 -> MD5.hmacv ~key [ seqbuf; buf ] |> take_96
  | Sha1 -> SHA1.hmacv ~key [ seqbuf; buf ]
  | Sha1_96 -> SHA1.hmacv ~key [ seqbuf; buf ] |> take_96
  | Sha2_256 -> SHA256.hmacv ~key [ seqbuf; buf ]
  | Sha2_512 -> SHA512.hmacv ~key [ seqbuf; buf ]

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let cipher_enc_dec enc ~key ~iv buf =
  let open Nocrypto.Cipher_block in
  match (snd key) with
  | Cipher.Aes_ctr_key key ->
    let f = if enc then AES.CTR.encrypt else AES.CTR.decrypt in
    let buf = f ~key ~ctr:iv buf in
    let blocks = (Cstruct.len buf) / AES.CTR.block_size |> Int64.of_int in
    let iv_len = Cstruct.len iv in
    let next_iv = Cstruct.create iv_len in
    Cstruct.blit iv 0 next_iv 0 iv_len;
    (* Update ctr with number of blocks *)
    Counter.add16 next_iv 0 blocks;
    buf, next_iv

  | Cipher.Aes_cbc_key key ->
    let f = if enc then AES.CBC.encrypt else AES.CBC.decrypt in
    let buf = f ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    buf, next_iv

let cipher_encrypt = cipher_enc_dec true
let cipher_decrypt = cipher_enc_dec false

let encrypt keys seq msg =
  let open Encode in
  let open Kex in
  let cipher = fst keys.cipher in
  let block_len = max 8 (Cipher.block_len cipher) in

  let buf = reserve Ssh.sizeof_pkt_hdr (create ()) |> put_message msg in
  (* packet_length + padding_length + payload - sequence_length *)
  let len = used buf in
  (* calculate padding *)
  let padlen =
    let x = block_len - (len mod block_len) in
    if x < 4 then x + block_len else x
  in
  assert (padlen < 256);
  let pkt = put_random padlen buf |> to_cstruct in
  Ssh.set_pkt_hdr_pkt_len pkt (Int32.of_int (Cstruct.len pkt));
  Ssh.set_pkt_hdr_pad_len pkt padlen;
  let digest = hmac keys.mac seq pkt in
  let enc, next_iv = cipher_encrypt ~key:keys.cipher ~iv:keys.iv pkt in
  (* XXX slow copy *)
  (Cstruct.append enc digest), next_iv

let decrypt keys seq buf =
  let open Kex in
  let cipher = fst keys.cipher in
  let block_len = max 8 (Cipher.block_len cipher) in
  let digest_len = Hmac.digest_len (fst keys.mac) in
  if (Cstruct.len buf) < (block_len + digest_len) then
    ok None
  else
    let dec, next_iv = cipher_decrypt ~key:keys.cipher ~iv:keys.iv buf in
    Decode.get_pkt dec >>= function
    | None -> ok None           (* partial packet *)
    | Some (payload, digest) ->
      if (Cstruct.len digest) < digest_len then
        ok None
      else
        let digest1 = Cstruct.set_len digest digest_len in
        let digest2 = hmac keys.mac seq payload in
        guard (Cstruct.equal digest1 digest2) "Bad digest" >>= fun () ->
        Decode.get_message payload >>= fun msg ->
        ok (Some (msg, buf, { keys with iv = next_iv }))
