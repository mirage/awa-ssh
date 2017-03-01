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

(*
 * NOTE: Sequence must be already in buf !!!
 *)
let hmac hkey buf =
  let open Hmac in
  let open Nocrypto.Hash in
  let hmac = fst hkey in
  let key = snd hkey in
  let take_96 buf =
    if (Cstruct.len buf) < 12 then
      failwith "digest is too short."
    else
      Cstruct.set_len buf 12
  in
  match hmac with
  | Md5 -> MD5.hmac ~key buf
  | Md5_96 -> MD5.hmac ~key buf |> take_96
  | Sha1 -> SHA1.hmac ~key buf
  | Sha1_96 -> SHA1.hmac ~key buf |> take_96
  | Sha2_256 -> SHA256.hmac ~key buf
  | Sha2_512 -> SHA512.hmac ~key buf

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let cipher_enc_dec enc ~key ~iv buf =
  let open Nocrypto.Cipher_block in
  match key with
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

let encrypt keys seq cipher mac msg =
  let open Encode in
  let block_len = max 8 (Cipher.block_len cipher) in

  (*
   * Reserve 4 bytes for the sequence number which will be used on hmac.
   * Reserve sizeof_pkt_hdr so we can patch len/padlen after knowing how much
   * we need.
   *)
  let buf = reserve (4 + Ssh.sizeof_pkt_hdr)  (create ()) |>
            put_message msg     (* payload *)
  in
  (* packet_length + padding_length + payload - sequence_length *)
  let len = (used buf) - 4 in
  (* calculate padding *)
  let padlen =
    let x = block_len - (len mod block_len) in
    if x < 4 then x + block_len else x
  in
  assert (padlen < 256);
  let buf = put_random padlen buf |> to_cstruct in
  Cstruct.BE.set_uint32 buf 0 seq;
  (* At this point buf points to the sequence number *)
  let pkt = Cstruct.shift buf 4 in
  Ssh.set_pkt_hdr_pkt_len pkt (Int32.of_int (Cstruct.len pkt));
  Ssh.set_pkt_hdr_pad_len pkt padlen;
  let hash = hmac keys.Kex.mac buf in
  let enc, next_iv = cipher_encrypt ~key:keys.Kex.enc ~iv:keys.Kex.iv pkt in
  (Cstruct.append enc hash), next_iv

let decrypt keys cipher mac buf =
  let len = Cstruct.len buf in
  let block_len = max 8 (Cipher.block_len cipher) in
  let digest_len = Hmac.digest_len mac in
  if len < (block_len + digest_len) then
    ok None
  else
    let dec, next_iv = cipher_decrypt ~key:keys.Kex.enc ~iv:keys.Kex.iv buf in
    let pkt_len = Ssh.get_pkt_hdr_pkt_len buf |> Int32.to_int in
    let pad_len = Ssh.get_pkt_hdr_pad_len buf in
    if len > (pkt_len + digest_len) then
      ok None
    else
      (* Pkt is the beggining of pkt, unterminated *)
      let pkt = Cstruct.set_len dec pkt_len in
      (* Payload is the beggining of message *)
      let payload = Cstruct.shift pkt (Ssh.sizeof_pkt_hdr + pad_len) in
      (* Check digest *)
      safe_shift buf pkt_len >>= fun digest ->
      let digest1 = Cstruct.set_len digest digest_len in
      let digest2 = hmac keys.Kex.mac pkt in
      guard (Cstruct.equal digest1 digest2) "Bad digest" >>= fun () ->
      (* Point to the end of buf *)
      safe_shift buf (pkt_len + digest_len) >>= fun buf ->
      Decode.get_message payload >>= fun msg ->
      ok (Some (msg, buf, next_iv))
