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

type t = {
  client_version : string option;      (* Without crlf *)
  server_version : string;             (* Without crlf *)
  client_kex : Cstruct.t option;       (* Last KEXINIT received *)
  server_kex : Cstruct.t;              (* Last KEXINIT sent by us *)
  neg_kex : Kex.negotiation option;    (* Negotiated KEX *)
  host_key : Nocrypto.Rsa.priv;        (* Server host key *)
  session_id : Cstruct.t option;       (* First calculated H *)
  keys_ctos : Kex.keys option;         (* Client to server (input) keys *)
  keys_stoc : Kex.keys option;         (* Server to cleint (output) keys *)
  new_keys_ctos : Kex.keys option;     (* Install when we receive NEWKEYS *)
  new_keys_stoc : Kex.keys option;     (* Install after we send NEWKEYS *)
  input_buffer : Cstruct.t;            (* Unprocessed input *)
}

let make host_key =
  let open Ssh in
  let banner_msg = Ssh_msg_version (version_banner ^ "\r\n") in
  let kex = Kex.make_pkt () in
  let kex_msg = Ssh.Ssh_msg_kexinit kex in
  let server_kex = Encode.buf_of_kex_pkt kex in
  let t = { client_version = None;
            server_version = version_banner;
            server_kex;
            client_kex = None;
            neg_kex = None;
            host_key;
            session_id = None;
            keys_ctos = None;
            keys_stoc = None;
            new_keys_ctos = None;
            new_keys_stoc = None;
            input_buffer = Cstruct.create 0 }
  in
  t, [ banner_msg; kex_msg ]

let of_buf t buf =
  { t with input_buffer = buf }

let patch_new_keys old_keys new_keys =
  let open Kex in
  let open Hmac in
  guard_some new_keys "No new_keys_ctos" >>= fun new_keys ->
  let new_seq = match old_keys with
    | None -> Int32.zero
    | Some keys -> keys.mac.seq
  in
  let new_mac = { new_keys.mac with seq = new_seq } in
  ok { new_keys with mac = new_mac }

let input_buf t buf =
  of_buf t (join_buf t.input_buffer buf)

let pop_msg2 t buf =
  let version t buf =
    Decode.get_version buf >>= fun (client_version, buf) ->
    match client_version with
    | None -> ok (t, None)
    | Some v ->
      let t = { t with client_version } in
      let msg = Ssh.Ssh_msg_version v in
      ok (t, Some msg)
  in
  let plain t buf =
    Packet.get_plain buf >>= function
    | None -> ok (t, None)
    | Some (pkt, buf) ->
      Packet.to_msg pkt >>= fun msg ->
      ok (of_buf t buf, Some msg)
  in
  let decrypt t keys buf =
    Packet.decrypt keys buf >>= function
    | None -> ok (t, None)
    | Some (pkt, buf, keys) ->
      let t = { t with keys_stoc = Some keys } in
      Packet.to_msg pkt >>= fun msg ->
      ok (of_buf t buf, Some msg)
  in
  match t.client_version with
  | None -> version t buf
  | Some _ ->
    match t.keys_stoc with
    | None -> plain t buf
    | Some keys -> decrypt t keys buf

let pop_msg t = pop_msg2 t t.input_buffer

let handle_msg t msg =
  let open Ssh in
  let open Nocrypto in
  match msg with
  | Ssh_msg_kexinit kex ->
    Decode.get_kex_pkt t.server_kex >>= fun (server_kex, _) ->
    Kex.negotiate ~s:server_kex ~c:kex
    >>= fun neg ->
    ok ({ t with client_kex = kex.input_buf; neg_kex = Some neg }, [])

  | Ssh_msg_kexdh_init e ->
    guard_some t.neg_kex "No negotiated kex" >>= fun neg ->
    guard_some t.client_version "No client version" >>= fun v_c ->
    guard_none t.new_keys_stoc "Already got new_keys_stoc" >>= fun () ->
    guard_none t.new_keys_ctos "Already got new_keys_ctos" >>= fun () ->
    guard_some t.client_kex "No client kex" >>= fun i_c ->
    let v_c = Cstruct.of_string v_c in
    let v_s = Cstruct.of_string t.server_version in
    let i_s = t.server_kex in
    let pub_host_key = Rsa.pub_of_priv t.host_key in
    let k_s = Encode.buf_of_key pub_host_key in
    Kex.(Dh.generate neg.kex_algorithm e) >>= fun (y, f, k) ->
    let h = Kex.Dh.compute_hash ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k in
    let signature = Rsa.PKCS1.sig_encode t.host_key h in
    let session_id = match t.session_id with None -> h | Some x -> x in
    let new_keys_ctos, new_keys_stoc = Kex.Dh.derive_keys k h session_id neg in
    ok ({t with session_id = Some session_id;
                new_keys_ctos = Some new_keys_ctos;
                new_keys_stoc = Some new_keys_stoc; },
        [ Ssh_msg_kexdh_reply (pub_host_key, f, signature);
          Ssh_msg_newkeys ])

  | Ssh_msg_newkeys ->
    patch_new_keys t.keys_ctos t.new_keys_ctos >>= fun new_keys_ctos ->
    ok ({ t with keys_ctos = Some new_keys_ctos;
                 new_keys_ctos = None },
        [])

  | Ssh_msg_version v ->
    ok ({ t with client_version = Some v }, [])

  | msg -> error ("unhandled msg: " ^ (message_to_string msg))

let output_msg t msg =
  (* Do state transitions *)
  (match msg with
   | Ssh.Ssh_msg_newkeys ->
     patch_new_keys t.keys_stoc t.new_keys_stoc >>= fun new_keys_stoc ->
     ok { t with keys_stoc = Some new_keys_stoc;
                 new_keys_stoc = None }
   | _ -> ok t)
  (* Build output buffer *)
  >>= fun t ->
  match t.keys_ctos with
  | None -> ok (t, Packet.plain msg)
  | Some keys ->
    let enc, keys = Packet.encrypt keys msg in
    ok ({ t with keys_ctos = Some keys }, enc)

let output_msgs t = function
  | [] -> invalid_arg "empty msg list"
  | [msg] -> output_msg t msg
  | msgs ->
    List.fold_left
      (fun a msg ->
         a >>= fun (t, buf) ->
         output_msg t msg >>= fun (t, msgbuf) ->
         ok (t, Cstruct.append buf msgbuf))
      (ok (t, Cstruct.create 0))
      msgs
