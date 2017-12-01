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

type result =
  | Send_msg of Ssh.message
  | Channel_exec of (int32 * string)
  | Channel_data of (int32 * string)
  | Channel_eof of int32
  | Disconnected of string

type t = {
  client_version : string option;         (* Without crlf *)
  server_version : string;                (* Without crlf *)
  client_kexinit : Ssh.kexinit option;    (* Last KEXINIT received *)
  server_kexinit : Ssh.kexinit;           (* Last KEXINIT sent by us *)
  neg_kex        : Kex.negotiation option;(* Negotiated KEX *)
  host_key       : Hostkey.priv;          (* Server host key *)
  session_id     : Cstruct.t option;      (* First calculated H *)
  keys_ctos      : Kex.keys;              (* Client to server (input) keys *)
  keys_stoc      : Kex.keys;              (* Server to cleint (output) keys *)
  new_keys_ctos  : Kex.keys option;       (* Install when we receive NEWKEYS *)
  new_keys_stoc  : Kex.keys option;       (* Install after we send NEWKEYS *)
  keying         : bool;                  (* keying = sent KEXINIT *)
  results        : result list;           (* Pending results used by Engine *)
  input_buffer   : Cstruct.t;             (* Unprocessed input *)
  expect         : Ssh.message_id option; (* Messages to expect, None if any *)
  auth_state     : Auth.state;            (* username * service in progress *)
  user_db        : Auth.db;               (* username database *)
  channels       : Channel.db;            (* Ssh channels *)
  ignore_next_packet : bool;              (* Ignore the next packet from the wire *)
}

let guard_msg t msg =
  let open Ssh in
  match t.expect with
  | None -> ok ()
  | Some MSG_DISCONNECT -> ok ()
  | Some MSG_IGNORE -> ok ()
  | Some MSG_DEBUG -> ok ()
  | Some id ->
    let msgid = message_to_id msg in
    guard (id = msgid) ("Unexpected message " ^ (message_id_to_string msgid))

let make host_key user_db =
  let open Ssh in
  let banner_msg = Msg_version version_banner in
  let server_kexinit = Kex.make_kexinit () in
  let kex_msg = Msg_kexinit server_kexinit in
  { client_version = None;
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
    keying = true;
    input_buffer = Cstruct.create 0;
    results = [ Send_msg banner_msg; Send_msg kex_msg ];
    expect = Some MSG_VERSION;
    auth_state = Auth.Preauth;
    user_db;
    channels = Channel.empty_db;
    ignore_next_packet = false }

(* t with updated keys from new_keys_ctos *)
let of_new_keys_ctos t =
  let open Kex in
  let open Hmac in
  guard_some t.new_keys_ctos "No new_keys_ctos" >>= fun new_keys_ctos ->
  guard (new_keys_ctos <> plaintext_keys) "Plaintext new keys" >>= fun () ->
  let new_mac_ctos = { new_keys_ctos.mac with seq = t.keys_ctos.mac.seq } in
  let new_keys_ctos = { new_keys_ctos with mac = new_mac_ctos } in
  ok { t with keys_ctos = new_keys_ctos; new_keys_ctos = None }

(* t with updated keys from new_keys_stoc *)
let of_new_keys_stoc t =
  let open Kex in
  let open Hmac in
  guard_some t.new_keys_stoc "No new_keys_stoc" >>= fun new_keys_stoc ->
  guard (new_keys_stoc <> plaintext_keys) "Plaintext new keys" >>= fun () ->
  let new_mac_stoc = { new_keys_stoc.mac with seq = t.keys_stoc.mac.seq } in
  let new_keys_stoc = { new_keys_stoc with mac = new_mac_stoc } in
  ok { t with keys_stoc = new_keys_stoc; new_keys_stoc = None; keying = false }

let rekey t =
  guard (t.keying = false) "already keying" >>= fun () ->
  let keys_stoc = Kex.reset_rekey t.keys_stoc in
  let server_kexinit = Kex.make_kexinit () in
  let t = { t with keys_stoc; server_kexinit; keying = true } in
  ok (t, server_kexinit)

let pop_msg2 t buf =
  let version t buf =
    Wire.get_version buf >>= fun (client_version, input_buffer) ->
    match client_version with
    | None -> ok (t, None)
    | Some v ->
      let msg = Ssh.Msg_version v in
      ok ({ t with input_buffer }, Some msg)
  in
  let decrypt t buf =
    Packet.decrypt t.keys_ctos buf >>= function
    | None -> ok (t, None)
    | Some (pkt, input_buffer, keys_ctos) ->
      let ignore_packet = t.ignore_next_packet in
      Packet.to_msg pkt >>= fun msg ->
      ok ({ t with keys_ctos; ignore_next_packet = false; input_buffer },
          if ignore_packet then None else Some msg)
  in
  match t.client_version with
  | None -> version t buf
  | Some _ -> decrypt t buf

let pop_msg t = pop_msg2 t t.input_buffer

let make_noreply t = ok (t, [])
let make_reply t msg = ok (t, [ Send_msg msg ])
let make_replies t msgs = ok (t, List.map (fun msg -> Send_msg msg) msgs)
let make_event t e = ok (t, [ e ])
let make_reply_with_event t msg e = ok (t, [ Send_msg msg; e ])
let make_disconnect t code s =
  ok (t, [ Send_msg (Ssh.disconnect_msg code s); Disconnected s ])

let rec input_userauth_request t username service auth_method =
  let open Ssh in
  let open Auth in
  let inc_nfailed t =
    match t.auth_state with
    | Preauth | Done -> error "Unexpected auth_state"
    | Inprogress (u, s, nfailed) ->
      ok ({ t with auth_state = Inprogress (u, s, succ nfailed) })
  in
  let disconnect t code s =
    inc_nfailed t >>= fun t ->
    make_disconnect t code s
  in
  let failure t =
    inc_nfailed t >>= fun t ->
    make_reply t (Msg_userauth_failure ([ "publickey"; "password" ], false))
  in
  let discard t = make_noreply t in
  let success t =
    make_reply { t with auth_state = Done; expect = None } Msg_userauth_success
  in
  let try_probe t pubkey =
    if pubkey <> Hostkey.Unknown then
      make_reply t (Msg_userauth_pk_ok pubkey)
    else
      failure t
  in
  let try_auth t b = if b then success t else failure t in
  let handle_auth t =
    (* XXX verify all fail cases, what should we do and so on *)
    guard_some t.session_id "No session_id" >>= fun session_id ->
    guard (service = "ssh-connection") "Bad service" >>= fun () ->
    match auth_method with
    | Pubkey (pubkey, None) ->        (* Public key probing *)
      try_probe t pubkey
    | Pubkey (pubkey, Some signed) -> (* Public key authentication *)
      try_auth t (by_pubkey username pubkey session_id service signed t.user_db)
    | Password (password, None) ->    (* Password authentication *)
      try_auth t (by_password username password t.user_db)
    (* Change of password, or Hostbased or Authnone won't be supported *)
    | Password (_, Some _) | Hostbased _ | Authnone -> failure t
  in
  (* See if we can actually authenticate *)
  match t.auth_state with
  | Done -> discard t (* RFC tells us we must discard requests if already authenticated *)
  | Preauth -> (* Recurse, but now Inprogress *)
    let t = { t with auth_state = Inprogress (username, service, 0) } in
    input_userauth_request t username service auth_method
  | Inprogress (prev_username, prev_service, nfailed) ->
    if service <> "ssh-connection" then
      disconnect t DISCONNECT_SERVICE_NOT_AVAILABLE
        (sprintf "Don't know service `%s`" service)
    else if prev_username <> username || prev_service <> service then
      disconnect t DISCONNECT_PROTOCOL_ERROR
        "Username or service changed during authentication"
    else if nfailed = 10 then
      disconnect t DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
        "Maximum authentication attempts reached"
    else if nfailed > 10 then
      error "Maximum authentication attempts reached, already sent disconnect"
    else
      handle_auth t

let input_channel_open t send_channel init_win_size max_pkt_size data =
  let open Ssh in
  let fail t code s =
    make_reply t
      (Msg_channel_open_failure
         (send_channel, channel_open_code_to_int code, s, ""))
  in
  let known data = match data with
    | Session -> true
    | X11 _ -> true
    | Forwarded_tcpip _ -> true
    | Direct_tcpip _ -> true
    | Raw_data _ -> false
  in
  let allowed data =
    match data with
    | Session -> true
    | X11 _ -> false
    | Forwarded_tcpip _ -> false
    | Direct_tcpip _ -> false
    | Raw_data _ -> false
  in
  let do_open t send_channel init_win_size max_pkt_size data =
    match
      Channel.add ~id:send_channel ~win:init_win_size
        ~max_pkt:max_pkt_size t.channels
    with
    | Error `No_channels_left ->
      fail t OPEN_RESOURCE_SHORTAGE "Maximum number of channels reached"
    | Ok (c, channels) ->
      let open Channel in
      make_reply { t with channels }
        (Msg_channel_open_confirmation
           (send_channel,
            c.us.id,
            c.us.win,
            c.us.max_pkt,
            Wire.blob_of_channel_data data))
  in
  if not (known data) then
    fail t OPEN_UNKNOWN_CHANNEL_TYPE ""
  else if not (allowed data) then (* XXX also covers unimplemented *)
    fail t OPEN_ADMINISTRATIVELY_PROHIBITED ""
  else
    do_open t send_channel init_win_size max_pkt_size data

let input_channel_request t recp_channel want_reply data =
  let open Ssh in
  let fail t =
    if want_reply then
      make_reply t (Msg_channel_failure recp_channel)
    else
      make_noreply t
  in
  let success t =
    if want_reply then
      make_reply t (Msg_channel_success recp_channel)
    else
      make_noreply t
  in
  let event t event =
    if want_reply then
      make_reply_with_event t (Msg_channel_success recp_channel) event
    else
      make_event t event
  in
  let handle t c data =
    match data with
    | Pty_req _ -> success t
    | X11_req _ -> fail t
    | Env (key, value) -> success t  (* TODO implement me *)
    | Shell -> fail t
    | Exec cmd -> event t (Channel_exec (c, cmd))
    | Subsystem _ -> fail t
    | Window_change _ -> fail t
    | Xon_xoff _ -> fail t
    | Signal _ -> fail t
    | Exit_status _ -> fail t
    | Exit_signal _ -> fail t
    | Raw_data _ -> fail t
  in
  (* Lookup the channel *)
  match Channel.lookup recp_channel t.channels with
  | None -> fail t
  | Some c -> handle t (Channel.id c) data

let input_msg t msg =
  let open Ssh in
  let open Nocrypto in
  guard_msg t msg >>= fun () ->
  match msg with
  | Msg_kexinit kex ->
    Kex.negotiate ~s:t.server_kexinit ~c:kex
    >>= fun neg ->
    let ignore_next_packet =
      kex.first_kex_packet_follows &&
      not (Kex.guessed_right ~s:t.server_kexinit ~c:kex)
    in
    let t = { t with client_kexinit = Some kex;
                     neg_kex = Some neg;
                     expect = Some MSG_KEXDH_INIT;
                     ignore_next_packet }
    in
    (* if keying, we already sent KEXINIT, nothing to do *)
    if t.keying then
      make_noreply t
    else (* Other side initiated rekeying, we have to kexinit again *)
      rekey t >>= fun (t, kexinit) ->
      make_reply t (Msg_kexinit kexinit)
  | Msg_kexdh_init e ->
    guard_some t.neg_kex "No negotiated kex" >>= fun neg ->
    guard_some t.client_version "No client version" >>= fun client_version ->
    guard_none t.new_keys_stoc "Already got new_keys_stoc" >>= fun () ->
    guard_none t.new_keys_ctos "Already got new_keys_ctos" >>= fun () ->
    guard_some t.client_kexinit "No client kex" >>= fun c ->
    Kex.(Dh.generate neg.kex_alg e) >>= fun (y, f, k) ->
    let pub_host_key = Hostkey.pub_of_priv t.host_key in
    let h = Kex.Dh.compute_hash
        ~v_c:(Cstruct.of_string client_version)
        ~v_s:(Cstruct.of_string t.server_version)
        ~i_c:c.rawkex
        ~i_s:(Wire.blob_of_kexinit t.server_kexinit)
        ~k_s:(Wire.blob_of_pubkey pub_host_key)
        ~e ~f ~k
    in
    let signature = Hostkey.sign t.host_key h in
    let session_id = match t.session_id with None -> h | Some x -> x in
    let new_keys_ctos, new_keys_stoc = Kex.Dh.derive_keys k h session_id neg in
    make_replies { t with session_id = Some session_id;
                          new_keys_ctos = Some new_keys_ctos;
                          new_keys_stoc = Some new_keys_stoc;
                          expect = Some MSG_NEWKEYS }
      [ Msg_kexdh_reply (pub_host_key, f, signature); Msg_newkeys ]
  | Msg_newkeys ->
    (* If this is the first time we keyed, we must take a service request *)
    let expect = if t.keys_ctos = Kex.plaintext_keys then
        Some MSG_SERVICE_REQUEST
      else
        None
    in
    (* Update keys *)
    of_new_keys_ctos t >>= fun t -> make_noreply { t with expect }
  | Msg_service_request service ->
    if service = "ssh-userauth" then
      make_reply { t with expect = Some MSG_USERAUTH_REQUEST }
        (Msg_service_accept service)
    else
      make_disconnect t DISCONNECT_SERVICE_NOT_AVAILABLE
        (sprintf "service %s not available" service)
  | Msg_userauth_request (username, service, auth_method) ->
    input_userauth_request t username service auth_method
  | Msg_channel_open (send_channel, init_win_size, max_pkt_size, data) ->
    input_channel_open t send_channel init_win_size max_pkt_size data
  | Msg_channel_request (recp_channel, want_reply, data) ->
    input_channel_request t recp_channel want_reply data
  | Msg_channel_close recp_channel ->
    let open Channel in
    (match lookup recp_channel t.channels with
     | None -> make_noreply t        (* XXX or should we disconnect ? *)
     | Some c ->
       let t = { t with channels = remove recp_channel t.channels } in
       (match c.state with
        | Open -> make_reply t (Msg_channel_close c.them.id)
        | Sent_close -> make_noreply t))
  | Msg_channel_data (recp_channel, data) ->
    (match Channel.lookup recp_channel t.channels with
     | None -> error "no such channel" (* XXX temporary for testing *)
     | Some c -> make_event t (Channel_data (Channel.id c, data)))
  | Msg_channel_eof recp_channel ->
    (match Channel.lookup recp_channel t.channels with
     | None -> error "no such channel" (* XXX temporary for testing *)
     | Some c -> make_event t (Channel_eof (Channel.id c)))
  | Msg_disconnect (code, s, _) -> make_event t (Disconnected s)
  | Msg_version v -> make_noreply { t with client_version = Some v;
                                           expect = Some MSG_KEXINIT }
  | msg -> error ("unhandled msg: " ^ (message_to_string msg))

let output_msg t msg =
  let t, buf =
    match msg with
    | Ssh.Msg_version v ->
      t, Cstruct.of_string (v ^ "\r\n")
    | msg ->
      let enc, keys = Packet.encrypt t.keys_stoc msg in
      { t with keys_stoc = keys }, enc
  in
  (* Do state transitions *)
  match msg with
  | Ssh.Msg_newkeys -> of_new_keys_stoc t >>= fun t -> ok (t, buf)
  | _ -> ok (t, buf)

module Engine = struct

  type poll_result =
    | No_input
    | Output of Cstruct.t
    | Channel_exec of (int32 * string)
    | Channel_data of (int32 * string)
    | Channel_eof of int32
    | Disconnected of string

  let input_buf t buf =
    if (List.length t.results) > 0 then
      error ("Can't add input while there are results pending." ^
             "Did you forget to call Server.poll until No_input ?")
    else
      ok { t with input_buffer = cs_join t.input_buffer buf }

  let send_event t e =
    ok { t with results = List.append t.results [ e ] }

  let send_msg t msg =
    ok { t with results = List.append t.results [ Send_msg msg ] }

  let maybe_rekey t =
    if not (Kex.should_rekey t.keys_stoc) || t.keying then
      ok t
    else
      rekey t >>= fun (t, kexinit) -> send_msg t (Ssh.Msg_kexinit kexinit)

  let result_to_poll t = function
    | Send_msg msg ->
      output_msg t msg >>= fun (t, msg_buf) ->
      maybe_rekey t >>= fun t ->
      Printf.printf ">>> %s\n%!" (Ssh.message_to_string msg);
      ok (t, Output msg_buf)
    | Channel_exec x -> ok (t, Channel_exec x)
    | Channel_data x -> ok (t, Channel_data x)
    | Channel_eof x -> ok (t, Channel_eof x)
    | Disconnected x -> ok (t, Disconnected x)

  let rec poll t =
    match t.results with
    | r :: results ->
      let t = { t with results } in
      result_to_poll t r >>= fun (t, pr) ->
      ok (t, pr)
    | [] ->
      pop_msg t >>= fun (t, msg) ->
      match msg with
      | None -> ok (t, No_input)
      | Some msg ->
        input_msg t msg >>= fun (t, results) ->
        poll { t with results }

  let send_channel_data t id data =
    match Channel.lookup id t.channels with
    | None -> error "No such channel"
    | Some c -> send_msg t (Ssh.Msg_channel_data (Channel.their_id c, data))

  let disconnect t =
    send_msg t (Ssh.disconnect_msg Ssh.DISCONNECT_BY_APPLICATION
                  "user disconnected")
    >>= fun t ->
    send_event t (Disconnected "you disconnected")
end
