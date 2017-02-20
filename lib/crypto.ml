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

(*
 * NOTE: Sequence must be already in buf !!!
 *)
let hmac ~key hmac buf =
  let open Hmac in
  let open Nocrypto.Hash in
  let take_16 buf =
    if (Cstruct.len buf) <= 16 then
      buf
    else
      Cstruct.sub buf 0 16
  in
  match hmac with
  | Md5 -> MD5.hmac ~key buf
  | Md5_96 -> MD5.hmac ~key buf |> take_16
  | Sha1 -> SHA1.hmac ~key buf
  | Sha1_96 -> SHA1.hmac ~key buf |> take_16
  | Sha2_256 -> SHA256.hmac ~key buf
  | Sha2_512 -> SHA512.hmac ~key buf

(* For some reason Nocrypto CTR modifies ctr in place, CBC returns next *)
let cipher_enc ~key ~iv buf =
  let open Nocrypto.Cipher_block in
  match key with
  | Cipher.Aes_ctr_key key ->
    let buf = AES.CTR.encrypt ~key ~ctr:iv buf in
    let blocks = (Cstruct.len buf) / AES.CTR.block_size |> Int64.of_int in
    let iv_len = Cstruct.len iv in
    let next_iv = Cstruct.create iv_len in
    Cstruct.blit iv 0 next_iv 0 iv_len;
    (* Update ctr with number of blocks *)
    Counter.add16 next_iv 0 blocks;
    buf, next_iv

  | Cipher.Aes_cbc_key key ->
    let buf = AES.CBC.encrypt ~key ~iv buf in
    let next_iv = AES.CBC.next_iv ~iv buf in
    buf, next_iv

let encrypt keys iv seq cipher mac msg =
  let open Ssh in
  let open Encode in
  let blen = max 8 (Cipher.block_len cipher) in

  (*
   * Reserve 4 bytes for the sequence number which will be used on hmac.
   * Reserve sizeof_pkt_hdr so we can patch len/padlen after knowing how much
   * we need.
   *)
  let buf = reserve (4 + sizeof_pkt_hdr)  (create ()) |>
            put_message msg     (* payload *)
  in
  (* packet_length + padding_length + payload - sequence_length *)
  let len = (used buf) - 4 in
  (* calculate padding *)
  let padlen =
    let x = blen - (len mod blen) in
    if x < 4 then x + blen else x
  in
  assert (padlen < 256);
  let buf = put_random padlen buf |> to_cstruct in
  Cstruct.BE.set_uint32 buf 0 seq;

  (* At this point buf points to the sequence number *)
  let pkt = Cstruct.shift buf 4 in
  Ssh.set_pkt_hdr_pkt_len pkt (Int32.of_int (Cstruct.len pkt));
  Ssh.set_pkt_hdr_pad_len pkt padlen;
  let hash = hmac ~key:keys.Kex.mac mac buf in
  let enc, next_iv = cipher_enc ~key:keys.Kex.enc ~iv:keys.Kex.iiv pkt in
  (Cstruct.append enc hash), next_iv
