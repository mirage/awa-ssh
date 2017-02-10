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

let version_banner = "SSH-2.0-awa_ssh_0.1"

(*
 * We keep i_c in original wire form, since coding and decoding is not an
 * identity function.
 *)
type t = {
  client_version : string option;      (* Without crlf *)
  server_version : string;             (* Without crlf *)
  client_kex : Cstruct.t option;       (* Last KEXINIT received *)
  server_kex : Cstruct.t;              (* Last KEXINIT sent by us *)
  neg_kex : Ssh.kex_neg option;        (* Negotiated KEX *)
  host_key : Nocrypto.Rsa.priv;        (* Server host key *)
}

let make host_key =
  let banner_buf = Printf.sprintf "%s\r\n" version_banner |> Cstruct.of_string in
  let kex = Ssh.make_kex () in
  let server_kex = Ssh.encode_kex kex in
  let t = { client_version = None;
            server_version = version_banner;
            server_kex;
            client_kex = None;
            neg_kex = None;
            host_key; }
  in
  t, Cstruct.append banner_buf (Ssh.encode_plain_pkt server_kex)

let input_msg t msgbuf =
  let open Ssh in
  decode_message msgbuf >>= fun msg ->
  match msg with
  | Ssh_msg_kexinit kex ->
    decode_kex t.server_kex >>= fun server_kex ->
    negotiate_kex ~s:server_kex ~c:kex
    >>= fun neg ->
    ok { t with client_kex = Some msgbuf; neg_kex = Some neg }

  | Ssh_msg_kexdh_init e ->
    guard_some t.neg_kex "No negotiated kex" >>= fun neg ->
    guard_some t.client_version "No client version" >>= fun v_c ->
    let v_c = Cstruct.of_string v_c in
    let v_s = Cstruct.of_string t.server_version in
    guard_some t.client_kex "No client kex" >>= fun i_c ->
    let i_s = t.server_kex in
    let k_s = encode_rsa (Nocrypto.Rsa.pub_of_priv t.host_key) in
    let hf = Nocrypto.Hash.SHA1.digestv in
    let g = match neg.kex_algorithm with
      | Diffie_hellman_group1_sha1  -> Nocrypto.Dh.Group.oakley_2 (* not a typo *)
      | Diffie_hellman_group14_sha1 -> Nocrypto.Dh.Group.oakley_14
    in
    dh_gen_keys g e >>= fun (y, f, k) ->
    dh_compute_hash ~hf ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k
    >>= fun h ->
    let signature = Nocrypto.Rsa.PKCS1.sig_encode t.host_key h in
    ok t
  | _ -> error "unhandled stuff"

