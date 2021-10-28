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

type event =
  | Channel_exec of (int32 * string)
  | Channel_data of (int32 * Cstruct.t)
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
  key_eol        : Mtime.t option;        (* Keys end of life, in ns *)
  expect         : Ssh.message_id option; (* Messages to expect, None if any *)
  auth_state     : Auth.state;            (* username * service in progress *)
  user_db        : Auth.db;               (* username database *)
  channels       : Channel.db;            (* Ssh channels *)
  ignore_next_packet : bool;              (* Ignore the next packet from the wire *)
}

let guard_msg t msg =
  let open Ssh in
  match t.expect with
  | None -> Ok ()
  | Some MSG_DISCONNECT -> Ok ()
  | Some MSG_IGNORE -> Ok ()
  | Some MSG_DEBUG -> Ok ()
  | Some id ->
    let msgid = message_to_id msg in
    guard (id = msgid) ("Unexpected message " ^ (message_id_to_string msgid))

let make host_key user_db =
  let open Ssh in
  let server_kexinit =
    Kex.make_kexinit Hostkey.preferred_algs Kex.server_supported ()
  in
  let banner_msg = Ssh.Msg_version version_banner in
  let kex_msg = Ssh.Msg_kexinit server_kexinit in
  { client_version = None;
    server_version = version_banner;
    server_kexinit;
    client_kexinit = None;
    neg_kex = None;
    host_key;
    session_id = None;
    keys_ctos = Kex.make_plaintext ();
    keys_stoc = Kex.make_plaintext ();
    new_keys_ctos = None;
    new_keys_stoc = None;
    keying = true;
    key_eol = None;
    expect = Some MSG_VERSION;
    auth_state = Auth.Preauth;
    user_db;
    channels = Channel.empty_db;
    ignore_next_packet = false },
  [ banner_msg; kex_msg ]

(* t with updated keys from new_keys_ctos *)
let of_new_keys_ctos t =
  let open Kex in
  let* new_keys_ctos = guard_some t.new_keys_ctos "No new_keys_ctos" in
  let* () = guard (is_keyed new_keys_ctos) "Plaintext new keys" in
  let new_keys_ctos = { new_keys_ctos with seq = t.keys_ctos.seq } in
  Ok { t with keys_ctos = new_keys_ctos; new_keys_ctos = None }

(* t with updated keys from new_keys_stoc *)
let of_new_keys_stoc t =
  let open Kex in
  let* new_keys_stoc = guard_some t.new_keys_stoc "No new_keys_stoc" in
  let* () = guard (is_keyed new_keys_stoc) "Plaintext new keys" in
  let new_keys_stoc = { new_keys_stoc with seq = t.keys_stoc.seq } in
  Ok { t with keys_stoc = new_keys_stoc; new_keys_stoc = None; keying = false }

let rekey t =
  match t.keying, (Kex.is_keyed t.keys_stoc) with
  | false, true ->              (* can't be keying and must be keyed *)
    let server_kexinit =
      Kex.make_kexinit Hostkey.preferred_algs Kex.server_supported ()
    in
    let t = { t with server_kexinit; keying = true } in
    Some (t, Ssh.Msg_kexinit server_kexinit)
  | _ -> None

let should_rekey t now =
  match t.key_eol with
  | None -> false
  | Some eol ->
    not t.keying &&
    Kex.should_rekey t.keys_stoc.Kex.tx_rx eol now

let maybe_rekey t now = if should_rekey t now then rekey t else None

let pop_msg2 t buf =
  let version t buf =
    let* v, i = Common.version buf in
    Ok (t, v, i)
  in
  let decrypt t buf =
    let* keys_ctos, msg, buf =
      Common.decrypt ~ignore_packet:t.ignore_next_packet t.keys_ctos buf
    in
    Ok ({ t with keys_ctos; ignore_next_packet = false }, msg, buf)
  in
  match t.client_version with
  | None -> version t buf
  | Some _ -> decrypt t buf

let make_noreply t = Ok (t, [], None)
let make_reply t msg = Ok (t, [ msg ], None)
let make_replies t msgs = Ok (t,  msgs, None)
let make_event t e = Ok (t, [], Some e)
let make_reply_with_event t msg e = Ok (t, [ msg ], Some e)
let make_disconnect t code s =
  Ok (t, [ Ssh.disconnect_msg code s ], Some (Disconnected s))

let rec input_userauth_request t username service auth_method =
  let open Ssh in
  let open Auth in
  let inc_nfailed t =
    match t.auth_state with
    | Preauth | Done -> Error "Unexpected auth_state"
    | Inprogress (u, s, nfailed) ->
      Ok ({ t with auth_state = Inprogress (u, s, succ nfailed) })
  in
  let disconnect t code s =
    let* t = inc_nfailed t in
    make_disconnect t code s
  in
  let failure t =
    let* t = inc_nfailed t in
    make_reply t (Msg_userauth_failure ([ "publickey"; "password" ], false))
  in
  let discard t = make_noreply t in
  let success t =
    make_reply { t with auth_state = Done; expect = None } Msg_userauth_success
  in
  let try_probe t pubkey =
    make_reply t (Msg_userauth_pk_ok pubkey)
  in
  let try_auth t b = if b then success t else failure t in
  let handle_auth t =
    (* XXX verify all fail cases, what should we do and so on *)
    let* session_id = guard_some t.session_id "No session_id" in
    let* () = guard (service = "ssh-connection") "Bad service" in
    match auth_method with
    | Pubkey (pubkey, None) ->        (* Public key probing *)
      try_probe t pubkey
    | Pubkey (pubkey, Some (alg, signed)) -> (* Public key authentication *)
      try_auth t (by_pubkey username alg pubkey session_id service signed t.user_db)
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
      Error "Maximum authentication attempts reached, already sent disconnect"
    else
      handle_auth t

let input_channel_open t send_channel init_win_size max_pkt_size data =
  let open Ssh in
  let fail t code s =
    make_reply t
      (Msg_channel_open_failure
         (send_channel, channel_open_code_to_int code, s, ""))
  in
  let known = function
    | Session -> true
    | X11 _ -> true
    | Forwarded_tcpip _ -> true
    | Direct_tcpip _ -> true
    | Raw_data _ -> false
  in
  let allowed = function
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
  let handle t c = function
    | Pty_req _ -> success t
    | X11_req _ -> fail t
    | Env (_key, _value) -> success t  (* TODO implement me *)
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

let input_msg t msg now =
  let open Ssh in
  let* () = guard_msg t msg in
  match msg with
  | Msg_kexinit kex ->
    let* neg = Kex.negotiate ~s:t.server_kexinit ~c:kex in
    let ignore_next_packet =
      kex.first_kex_packet_follows &&
      not (Kex.guessed_right ~s:t.server_kexinit ~c:kex)
    in
    let t = { t with client_kexinit = Some kex;
                     neg_kex = Some neg;
                     expect = Some MSG_KEX_0; (* TODO needs fix *)
                     ignore_next_packet }
    in
    (match rekey t with
     | None -> make_noreply t   (* either already rekeying or not keyed *)
     | Some (t, kexinit) -> make_reply t kexinit)
  | Msg_kex (id, data) ->
    begin
      let* m = Wire.dh_kexdh_of_kex id data in
      match m with
      | Msg_kexdh_init e ->
        let* neg = guard_some t.neg_kex "No negotiated kex" in
        let* client_version = guard_some t.client_version "No client version" in
        let* () = guard_none t.new_keys_stoc "Already got new_keys_stoc" in
        let* () = guard_none t.new_keys_ctos "Already got new_keys_ctos" in
        let* c = guard_some t.client_kexinit "No client kex" in
        let* f, k = Kex.(Dh.generate neg.kex_alg e) in
        let pub_host_key = Hostkey.pub_of_priv t.host_key in
        let h = Kex.Dh.compute_hash ~signed:true neg
            ~v_c:client_version
            ~v_s:t.server_version
            ~i_c:c.rawkex
            ~i_s:(Wire.blob_of_kexinit t.server_kexinit)
            ~k_s:pub_host_key
            ~e ~f ~k
        in
        let signature = Hostkey.sign neg.server_host_key_alg t.host_key h in
        Format.printf "shared is %a signature is %a (hash %a)\n%!"
          Cstruct.hexdump_pp (Mirage_crypto_pk.Z_extra.to_cstruct_be f)
          Cstruct.hexdump_pp signature Cstruct.hexdump_pp h;
        let session_id = match t.session_id with None -> h | Some x -> x in
        let* new_keys_ctos, new_keys_stoc, key_eol =
          Kex.Dh.derive_keys k h session_id neg now
        in
        let signature = neg.server_host_key_alg, signature in
        make_replies { t with session_id = Some session_id;
                              new_keys_ctos = Some new_keys_ctos;
                              new_keys_stoc = Some new_keys_stoc;
                              key_eol = Some key_eol;
                              expect = Some MSG_NEWKEYS }
          [ Msg_kexdh_reply (pub_host_key, f, signature); Msg_newkeys ]
      | _ ->
        Error "unexpected KEX message"
    end
  | Msg_newkeys ->
    (* If this is the first time we keyed, we must take a service request *)
    let expect = if not (Kex.is_keyed t.keys_ctos)  then
        Some MSG_SERVICE_REQUEST
      else
        None
    in
    (* Update keys *)
    let* t = of_new_keys_ctos t in
    make_noreply { t with expect }
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
        | Open -> make_reply_with_event
                    t (Msg_channel_close c.them.id) (Channel_eof recp_channel)
        | Sent_close -> make_noreply t))
  | Msg_channel_data (recp_channel, data) ->
    let* c =
      guard_some (Channel.lookup recp_channel t.channels) "no such channel"
    in
    let* c, data, adjust = Channel.input_data c data in
    let channels = Channel.update c t.channels in
    let t = { t with channels } in
    let e = (Channel_data (Channel.id c, data)) in
    (match adjust with
     | None -> make_event t (Channel_data (Channel.id c, data))
     | Some adjust -> make_reply_with_event t adjust e)
  | Msg_channel_window_adjust (recp_channel, len) ->
    let* c =
      guard_some (Channel.lookup recp_channel t.channels) "no such channel"
    in
    let* c, msgs = Channel.adjust_window c len in
    let channels = Channel.update c t.channels in
    make_replies { t with channels } msgs
  | Msg_channel_eof recp_channel ->
    let* c =
      guard_some (Channel.lookup recp_channel t.channels) "no such channel"
    in
    make_event t (Channel_eof (Channel.id c))
  | Msg_disconnect (_, s, _) -> make_event t (Disconnected s)
  | Msg_version v -> make_noreply { t with client_version = Some v;
                                           expect = Some MSG_KEXINIT }
  | msg -> Error ("unhandled msg: " ^ (message_to_string msg))

let output_msg t msg =
  let buf, keys_stoc = Common.output_msg t.keys_stoc msg in
  let t = { t with keys_stoc } in
  (* Do state transitions *)
  match msg with
  | Ssh.Msg_newkeys ->
    let* t = of_new_keys_stoc t in
    Ok (t, buf)
  | _ -> Ok (t, buf)

let output_channel_data t id data =
  let* () = guard (Cstruct.length data > 0) "empty data" in
  let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
  let* c, frags = Channel.output_data c data in
  Ok ({ t with channels = Channel.update c t.channels }, frags)
