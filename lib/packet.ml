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

open Util

let len_off = 0

let get_pkt_len buf =
  Cstruct.BE.get_uint32 buf len_off |> Int32.to_int
let set_pkt_len buf v =
  Cstruct.BE.set_uint32 buf len_off (Int32.of_int v)

let pad_len_off = 4

let get_pad_len buf = Cstruct.get_uint8 buf pad_len_off
let set_pad_len buf v = Cstruct.set_uint8 buf pad_len_off v

let sizeof_pkt_hdr = 5

let get_payload buf =
  let* () = guard (Cstruct.length buf >= 5) "Buf too short" in
  let pkt_len = get_pkt_len buf in
  let pad_len = get_pad_len buf in
  let* () = guard (pkt_len > 0 && pkt_len < Ssh.max_pkt_len) "Bogus pkt len" in
  let* () = guard (pad_len < pkt_len) "Bogus pad len" in
  let* () = guard (Cstruct.length buf = pkt_len + 4) "Bogus buf len" in
  let payload_len = pkt_len - pad_len - 1 in
  let* () = guard (payload_len > 0) "Bogus payload_len" in
  let payload = Cstruct.sub buf 5 payload_len in
  Ok payload


let hmac mac seq buf =
  let hmac = mac.Hmac.hmac in
  let key = mac.Hmac.key in
  let seqbuf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 seqbuf 0 seq;
  Hmac.hmacv hmac ~key [ seqbuf; buf ]

let peek_len cipher seq block_len buf =
  assert (block_len <= Cstruct.length buf);
  let buf = Cstruct.sub buf 0 block_len in
  let* hdr, _ = Cipher.decrypt ~len:true seq cipher buf in
  Ok (get_pkt_len hdr)

let partial buf =
  if Cstruct.length buf < Ssh.max_pkt_len then
    Ok None
  else
    Error "Buffer is too big"

let to_msg pkt =
  Result.bind (get_payload pkt) Wire.get_message

let decrypt keys buf =
  let open Ssh in
  let cipher = keys.Kex.cipher in
  let mac = keys.Kex.mac in
  let seq = keys.Kex.seq in
  let block_len = max 8 (Cipher.block_len cipher.Cipher.cipher) in
  let digest_len = Hmac.(digest_len mac.hmac)
  and mac_len = Cipher.(mac_len cipher.Cipher.cipher)
  in
  if Cstruct.length buf < max sizeof_pkt_hdr (digest_len + mac_len + block_len) then
    partial buf
  else
    let* pkt_len = peek_len cipher seq block_len buf in
    let* () =
      guard (pkt_len > 0 && pkt_len < max_pkt_len) "decrypt: Bogus pkt len"
    in
    (* 4 is pkt_len field itself *)
    if Cstruct.length buf < pkt_len + 4 + digest_len + mac_len then
      partial buf
    else
      let pkt_enc, digest1 = Cstruct.split buf (pkt_len + 4 + mac_len) in
      let tx_rx = Int64.(add keys.Kex.tx_rx (Cstruct.length pkt_enc - mac_len |> of_int)) in
      let* pkt_dec, cipher = Cipher.decrypt ~len:false seq cipher pkt_enc in
      let digest1 = Cstruct.sub digest1 0 digest_len in
      let digest2 = hmac mac seq pkt_dec in
      let* () =
        guard (Cstruct.equal digest1 digest2) "decrypt: Bad digest"
      in
      let pad_len = get_pad_len pkt_dec in
      let* () =
        guard (pad_len >= 4 && pad_len <= 255 && pad_len < pkt_len)
          "decrypt: Bogus pad len"
      in
      let buf = Cstruct.shift buf (4 + pkt_len + mac_len + digest_len) in
      let keys = Kex.{ cipher; mac; seq = Int32.succ keys.Kex.seq; tx_rx } in
      Ok (Some (pkt_dec, buf, keys))

let encrypt keys msg =
  let cipher = keys.Kex.cipher in
  let mac = keys.Kex.mac in
  let seq = keys.Kex.seq in
  let block_len = max 8 (Cipher.block_len cipher.Cipher.cipher) in
  (* packet_length + padding_length + payload - sequence_length *)
  let buf = Dbuf.reserve sizeof_pkt_hdr (Dbuf.create ()) |> Wire.put_message msg in
  let len = Dbuf.used buf in
  let len = if Cipher.aead cipher.Cipher.cipher then len - 4 else len in
  (* calculate padding *)
  let padlen =
    let x = block_len - (len mod block_len) in
    if x < 4 then x + block_len else x
  in
  assert (padlen >= 4 && padlen <= 255);
  let pkt = Wire.put_random padlen buf |> Dbuf.to_cstruct in
  set_pkt_len pkt (Cstruct.length pkt - 4);
  set_pad_len pkt padlen;
  let digest = hmac mac seq pkt in
  let enc, cipher = Cipher.encrypt ~len:false seq cipher pkt in
  let packet = Cstruct.append enc digest in
  let tx_rx = Int64.add keys.Kex.tx_rx (Cstruct.length packet |> Int64.of_int) in
  let keys = Kex.{ cipher; mac; seq = Int32.succ keys.Kex.seq; tx_rx } in
  packet, keys
