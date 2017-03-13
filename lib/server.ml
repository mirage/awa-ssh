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
open Util

let version_banner = "SSH-2.0-awa_ssh_0.1"

type t = {
  client_version : string option;         (* Without crlf *)
  server_version : string;                (* Without crlf *)
  client_kexinit : Ssh.kexinit option;    (* Last KEXINIT received *)
  server_kexinit : Ssh.kexinit;           (* Last KEXINIT sent by us *)
  neg_kex        : Kex.negotiation option;(* Negotiated KEX *)
  host_key       : Nocrypto.Rsa.priv;     (* Server host key *)
  session_id     : Cstruct.t option;      (* First calculated H *)
  keys_ctos      : Kex.keys;              (* Client to server (input) keys *)
  keys_stoc      : Kex.keys;              (* Server to cleint (output) keys *)
  new_keys_ctos  : Kex.keys option;       (* Install when we receive NEWKEYS *)
  new_keys_stoc  : Kex.keys option;       (* Install after we send NEWKEYS *)
  input_buffer   : Cstruct.t;             (* Unprocessed input *)
  expect         : Ssh.message_id option  (* Which messages are expected, None if any *)
}

let guard_msg t msg =
  let open Ssh in
  match t.expect with
  | None -> ok ()
  | Some SSH_MSG_DISCONNECT -> ok ()
  | Some SSH_MSG_IGNORE -> ok ()
  | Some SSH_MSG_DEBUG -> ok ()
  | Some id ->
    let msgid = message_to_id msg in
    guard (id = msgid) ("Unexpected message " ^ (message_id_to_string msgid))

let make host_key =
  let open Ssh in
  let banner_msg = Ssh_msg_version version_banner in
  let server_kexinit = Kex.make_kexinit () in
  let kex_msg = Ssh.Ssh_msg_kexinit server_kexinit in
  let t = { client_version = None;
            server_version = version_banner;
            server_kexinit;
            client_kexinit = None;
            neg_kex = None;
            host_key;
            session_id = None;
            keys_ctos = Kex.plaintext_keys;
            keys_stoc = Kex.plaintext_keys;
            new_keys_ctos = None;
            new_keys_stoc = None;
            input_buffer = Cstruct.create 0;
            expect = Some SSH_MSG_VERSION; }
  in
  t, [ banner_msg; kex_msg ]

let of_buf t buf =
  { t with input_buffer = buf }

let patch_new_keys old_keys new_keys =
  let open Kex in
  let open Hmac in
  guard_some new_keys "No new_keys_ctos" >>= fun new_keys ->
  let new_mac = { new_keys.mac with seq = old_keys.mac.seq } in
  ok { new_keys with mac = new_mac }

let input_buf t buf =
  of_buf t (cs_join t.input_buffer buf)

let pop_msg2 t buf =
  let version t buf =
    Decode.get_version buf >>= fun (client_version, buf) ->
    match client_version with
    | None -> ok (t, None)
    | Some v ->
      let msg = Ssh.Ssh_msg_version v in
      ok (of_buf t buf, Some msg)
  in
  let decrypt t buf =
    Packet.decrypt t.keys_ctos buf >>= function
    | None -> ok (t, None)
    | Some (pkt, buf, keys_ctos) ->
      Packet.to_msg pkt >>= fun msg ->
      let t = { t with keys_ctos } in
      ok (of_buf t buf, Some msg)
  in
  match t.client_version with
  | None -> version t buf
  | Some _ -> decrypt t buf

let pop_msg t = pop_msg2 t t.input_buffer

let handle_msg t msg =
  let open Ssh in
  let open Nocrypto in
  guard_msg t msg >>= fun () ->
  match msg with
  | Ssh_msg_kexinit kex ->
    guard_some kex.input_buf "No kex input_buf kex" >>= fun _ ->
    Kex.negotiate ~s:t.server_kexinit ~c:kex
    >>= fun neg ->
    ok ({ t with client_kexinit = Some kex;
                 neg_kex = Some neg;
                 expect = Some SSH_MSG_KEXDH_INIT },
        [])
  | Ssh_msg_kexdh_init e ->
    guard_some t.neg_kex "No negotiated kex" >>= fun neg ->
    guard_some t.client_version "No client version" >>= fun client_version ->
    guard_none t.new_keys_stoc "Already got new_keys_stoc" >>= fun () ->
    guard_none t.new_keys_ctos "Already got new_keys_ctos" >>= fun () ->
    guard_some t.client_kexinit "No client kex" >>= fun c ->
    guard_some c.input_buf "No kex input_buf" >>= fun client_kexinit ->
    Kex.(Dh.generate neg.kex_alg e) >>= fun (y, f, k) ->
    let pub_host_key = Rsa.pub_of_priv t.host_key in
    let h = Kex.Dh.compute_hash
        ~v_c:(Cstruct.of_string client_version)
        ~v_s:(Cstruct.of_string t.server_version)
        ~i_c:client_kexinit
        ~i_s:(Encode.blob_of_kexinit t.server_kexinit)
        ~k_s:(Encode.blob_of_key pub_host_key)
        ~e ~f ~k
    in
    let signature = Kex.sign t.host_key h in
    let session_id = match t.session_id with None -> h | Some x -> x in
    let new_keys_ctos, new_keys_stoc = Kex.Dh.derive_keys k h session_id neg in
    ok ({t with session_id = Some session_id;
                new_keys_ctos = Some new_keys_ctos;
                new_keys_stoc = Some new_keys_stoc;
                expect = Some SSH_MSG_NEWKEYS },
        [ Ssh_msg_kexdh_reply (pub_host_key, f, signature);
          Ssh_msg_newkeys ])
  | Ssh_msg_newkeys ->
    (* If this is the first time we keyed, we must take a service request *)
    let expect = if t.keys_ctos = Kex.plaintext_keys then
        Some SSH_MSG_SERVICE_REQUEST
      else
        None
    in
    patch_new_keys t.keys_ctos t.new_keys_ctos >>= fun new_keys_ctos ->
    (* paranoia *)
    assert (new_keys_ctos <> Kex.plaintext_keys);
    ok ({ t with keys_ctos = new_keys_ctos;
                 new_keys_ctos = None;
                 expect },
        [])
  | Ssh_msg_service_request service ->
    if service = "ssh-userauth" then
      ok ({ t with expect = Some SSH_MSG_USERAUTH_REQUEST },
          [ Ssh_msg_service_accept service ])
    else
      (* XXX need to tell user to close socket when we send a disconnect. *)
      let msg =
        Ssh_msg_disconnect
          (SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
           (sprintf "service %s not available" service), "")
      in
      ok (t, [ msg ])
  | Ssh_msg_userauth_request (user, service, auth_method) ->
    guard (service = "ssh-connection") ("Bad service: " ^ service) >>= fun () ->
    let fail t = ok (t, [ Ssh_msg_userauth_failure ([ "password" ], false) ]) in
    (* XXX must check if user or service ever changes and disconnect *)
    (match auth_method with
     | Publickey _ -> fail t                      (* TODO *)
     | Password (password, None) -> ok (t, [])    (* TODO *)
     | Password (password, Some oldpassword) -> fail t (* Change of password *)
     | Hostbased _ -> fail t                      (* TODO *)
     | Authnone -> fail t)                        (* Always fail *)
  | Ssh_msg_version v ->
    ok ({ t with client_version = Some v;
                 expect = Some SSH_MSG_KEXINIT }, [])
  | msg -> error ("unhandled msg: " ^ (message_to_string msg))

let output_msg t msg =
  (match msg with
   | Ssh.Ssh_msg_version v ->
     ok (t, Cstruct.of_string (v ^ "\r\n"))
   | msg ->
     let enc, keys = Packet.encrypt t.keys_stoc msg in
     ok ({ t with keys_stoc = keys }, enc))
  >>= fun (t, buf) ->
  (* Do state transitions *)
  match msg with
  | Ssh.Ssh_msg_newkeys ->
    patch_new_keys t.keys_stoc t.new_keys_stoc >>= fun new_keys_stoc ->
    let t = { t with keys_stoc = new_keys_stoc;
                     new_keys_stoc = None }
    in
    ok (t, buf)
  | _ -> ok (t, buf)

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
