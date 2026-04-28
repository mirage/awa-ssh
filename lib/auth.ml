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

let to_hash name alg pubkey session_id service =
  let open Wire in
  let b = Bytes.create 0xffff in (* TODO: length *)
  let off = put_string (b, 0) session_id in
  let off = put_message_id (b, off) Ssh.MSG_USERAUTH_REQUEST in
  let off = put_string (b, off) name in
  let off = put_string (b, off) service in
  let off = put_string (b, off) "publickey" in
  let off = put_bool (b, off) true in
  let off = put_string (b, off) (Hostkey.alg_to_string alg) in
  let off = put_pubkey (b, off) pubkey in
  String.sub (Bytes.unsafe_to_string b) 0 off

let sign name alg key session_id service =
  let data = to_hash name alg (Hostkey.pub_of_priv key) session_id service in
  Hostkey.sign alg key data

let verify_signature name alg pubkey session_id service signed =
  let unsigned = to_hash name alg pubkey session_id service in
  Hostkey.verify alg pubkey ~unsigned ~signed
