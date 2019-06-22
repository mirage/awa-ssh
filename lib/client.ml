(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed!
*)

open Rresult.R
open Util

let service = "ssh-connection"

type event = [
  | `Established of int32
  | `Channel_data of int32 * Cstruct.t
  | `Channel_eof of int32
  | `Channel_exit_status of int32 * int32
  | `Disconnected
]

let pp_event ppf = function
  | `Established id -> Format.fprintf ppf "established id %lu" id
  | `Channel_data (id, data) ->
    Format.fprintf ppf "data %lu: %s" id (Cstruct.to_string data)
  | `Channel_eof id -> Format.fprintf ppf "eof %lu" id
  | `Channel_exit_status (id, r) -> Format.fprintf ppf "exit %lu with %lu" id r
  | `Disconnected -> Format.fprintf ppf "disconnected"

type state =
  | Init of string * Ssh.kexinit
  | Received_version of string * Ssh.kexinit * string
  | Negotiated_kex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * Nocrypto.Dh.secret * Ssh.mpint
  | Newkeys_before_auth of Kex.keys * Kex.keys
  | Requested_service of string
  | Userauth_request of Ssh.auth_method
  | Opening_channel of Channel.channel_end
  | Established

type t = {
  state : state ;
  session_id     : Cstruct.t option;
  keys_ctos      : Kex.keys;
  keys_stoc      : Kex.keys;
  keying         : bool;
  key_eol        : Mtime.t option;
  channels       : Channel.db;
  linger  : Cstruct.t;
  username : string ;
  key : Hostkey.priv ;
  server_key : Nocrypto.Rsa.pub ;
}

let rotate_keys_ctos t new_keys_ctos =
  let open Kex in
  let new_mac_ctos = { new_keys_ctos.mac with seq = t.keys_ctos.mac.seq } in
  let new_keys_ctos = { new_keys_ctos with mac = new_mac_ctos } in
  { t with keys_ctos = new_keys_ctos }

let rotate_keys_stoc t new_keys_stoc =
  let open Kex in
  let new_mac_stoc = { new_keys_stoc.mac with seq = t.keys_stoc.mac.seq } in
  let new_keys_stoc = { new_keys_stoc with mac = new_mac_stoc } in
  { t with keys_stoc = new_keys_stoc; keying = false }

let debug_msg prefix = function
  | Ssh.Msg_channel_data (id, data) ->
    Printf.printf "%s (Msg_data %d bytes for %lu)\n%!" prefix (Cstruct.len data) id
  | msg -> Printf.printf "%s %s\n%!" prefix (Ssh.message_to_string msg)

let output_msg t msg =
  let buf, keys_ctos = Common.output_msg t.keys_ctos msg in
  let t = { t with keys_ctos } in
  debug_msg ">>>" msg;
  (* Do state transitions *)
  match t.state with
  | Newkeys_before_auth (my_keys, _) ->
    Printf.printf "rotating ctos keys\n%!";
    let t' = rotate_keys_ctos t my_keys in
    t', buf
  | _ -> t, buf

let output_msgs t msgs =
  let t', data = List.fold_left (fun (t, acc) msg ->
      let t', buf = output_msg t msg in
      (t', buf :: acc))
      (t, []) msgs
  in
  t', List.rev data

let make username key server_key () =
  let open Ssh in
  let client_kexinit = Kex.make_kexinit () in
  let banner_msg = Ssh.Msg_version version_banner in
  let kex_msg = Ssh.Msg_kexinit client_kexinit in
  let t = { state = Init (version_banner, client_kexinit);
            session_id = None;
            keys_ctos = Kex.make_plaintext ();
            keys_stoc = Kex.make_plaintext ();
            keying = true;
            key_eol = None;
            linger = Cstruct.empty;
            channels = Channel.empty_db;
            username ; key ; server_key
          }
  in
  output_msgs t [ banner_msg ; kex_msg ]

let handle_kexinit t c_v ckex s_v skex =
  Kex.negotiate ~s:skex ~c:ckex >>= fun neg ->
  let secret, my_pub = Kex.Dh.secret_pub neg.kex_alg in
  ok ({ t with state = Negotiated_kex (c_v, ckex, s_v, skex, neg, secret, my_pub) },
      [ Ssh.Msg_kexdh_init my_pub], [])

let hostkey p =
    let pubkey = Wire.blob_of_pubkey p in
    Cstruct.to_string (Nocrypto.Base64.encode pubkey)

let handle_kexdh_reply t now c_v ckex s_v skex neg secret my_pub pubkey their_dh signature =
  Kex.Dh.shared neg.Kex.kex_alg secret their_dh >>= fun shared ->
  let h = Kex.Dh.compute_hash
      ~v_c:(Cstruct.of_string c_v)
      ~v_s:(Cstruct.of_string s_v)
      ~i_c:(Wire.blob_of_kexinit ckex)
      ~i_s:skex.Ssh.rawkex
      ~k_s:(Wire.blob_of_pubkey pubkey)
      ~e:my_pub ~f:their_dh ~k:shared
  in
  Printf.printf "hostkey is %s\n%!" (hostkey pubkey);
  if match pubkey with Unknown -> false | Rsa_pub p -> p = t.server_key then
    if Hostkey.verify pubkey ~unsigned:h ~signed:signature then begin
      Printf.printf "verified kexdh_reply!\n%!";
      let session_id = match t.session_id with None -> h | Some x -> x in
      Kex.Dh.derive_keys shared h session_id neg now
      >>| fun (new_keys_ctos, new_keys_stoc, key_eol) ->
      { t with
        state = Newkeys_before_auth (new_keys_ctos, new_keys_stoc) ;
        session_id = Some session_id ; key_eol = Some key_eol },
      [ Ssh.Msg_newkeys ], []
    end else begin
      Printf.printf "verified kexdh_reply FAILED!\n%!";
      Error "couldn't verify kex"
    end
  else
 begin
   Printf.printf "server key mismatch!\n%!";
   Error "server key mismatch"
 end

let handle_newkeys_before_auth t keys =
  Printf.printf "rotating stoc keys\n%!";
  let t' = rotate_keys_stoc t keys in
  let service = "ssh-userauth" in
  Ok ({ t' with state = Requested_service service },
      [ Ssh.Msg_service_request service ], [])

let service_accepted t = function
  | "ssh-userauth" ->
    Ok ({ t with state = Userauth_request Authnone },
        [ Ssh.Msg_userauth_request (t.username, service, Authnone) ],
        [])
  | service -> Error ("unknown service: " ^ service)

let handle_auth_failure t _ = function
  | [] -> Error "no authentication method left"
  | xs when List.mem "publickey" xs ->
    let pub = Hostkey.pub_of_priv t.key in
    let met = Ssh.Pubkey (pub, None) in
    Ok ({ t with state = Userauth_request met },
        [ Ssh.Msg_userauth_request (t.username, service, met) ],
        [])
  | _ -> Error "no supported authentication methods left"

let handle_pk_ok t m pk = match m with
  | Ssh.Pubkey (pub, None) when pub = pk ->
    let session_id = match t.session_id with None -> assert false | Some x -> x in
    let signature = Auth.sign t.username t.key session_id service in
    let met = Ssh.Pubkey (Hostkey.pub_of_priv t.key, Some signature) in
    Ok ({ t with state = Userauth_request met },
        [ Ssh.Msg_userauth_request (t.username, service, met) ],
        [])
  | _ -> Error "not sure how we ended in pk ok now"

let open_channel t _m =
  if Channel.is_empty t.channels then
    let channel, msg =
      let id = 0l
      and win = Ssh.channel_win_len
      and max_pkt = Ssh.channel_max_pkt_len
      in
      Channel.make_end id win max_pkt,
      (id, win, max_pkt, Ssh.Session)
    in
    Ok ({ t with state = Opening_channel channel }, [ Ssh.Msg_channel_open msg ], [])
  else
    Error "not sure what to do, there's already a channel"

let open_channel_success t us our_id their_id win max_pkt _data =
  if us.Channel.id = our_id then
    let them = Channel.make_end their_id win max_pkt in
    let c = Channel.make ~us ~them in
    let channels = Channel.update c t.channels in
    Ok ({ t with channels ; state = Established }, [], [ `Established our_id ])
  else
    Error (Printf.sprintf "channel ids do not match (our %lu their %lu)"
             us.Channel.id our_id)

let input_msg t msg now =
  let open Ssh in
  match t.state, msg with
  | Init (c, kex), Msg_version v ->
    Ok ({ t with state = Received_version (c, kex, v) }, [], [])
  | Received_version (c_v, c_kex, s_v), Msg_kexinit skex ->
    handle_kexinit t c_v c_kex s_v skex
  | Negotiated_kex (c_v, c_kex, s_v, s_kex, neg, sec, my_pub), Msg_kexdh_reply (pub, their_dh, signature) ->
    handle_kexdh_reply t now c_v c_kex s_v s_kex neg sec my_pub pub their_dh signature
  | Newkeys_before_auth (_, keys), Msg_newkeys -> handle_newkeys_before_auth t keys
  | Requested_service s, Msg_service_accept s' when s = s' ->
    service_accepted t s
  | Userauth_request m, Msg_userauth_failure (methods, _) ->
    handle_auth_failure t m methods
  | Userauth_request m, Msg_userauth_pk_ok pk ->
    handle_pk_ok t m pk
  | Userauth_request m, Msg_userauth_success ->
    open_channel t m
  | Opening_channel us, Msg_channel_open_confirmation (a, b, c, d, e) ->
    open_channel_success t us a b c d e
  | _, Msg_global_request (_, want_reply, Unknown_request _) ->
    Printf.printf "ignoring unknown global request (want reply %B)\n%!" want_reply;
    Ok (t, [], [])
  | _, Msg_debug (_, msg, lang) ->
    Printf.printf "ignoring debug %s (lang %s)\n%!" msg lang;
    Ok (t, [], [])
  | Established, Msg_channel_data (id, data) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Channel.input_data c data >>| fun (c, data, adjust) ->
    let channels = Channel.update c t.channels in
    let t = { t with channels } in
    let e = `Channel_data (Channel.id c, data) in
    (match adjust with
     | None -> t, [], [ e ]
     | Some adjust -> t, [ adjust ], [ e ])
  | Established, Msg_channel_window_adjust (id, len) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Channel.adjust_window c len >>= fun (c, msgs) ->
    let channels = Channel.update c t.channels in
    Ok ({ t with channels }, msgs, [])
  | Established, Msg_channel_eof id ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Ok (t, [], [ `Channel_eof (Channel.id c) ])
  | Established, Msg_channel_request (id, false, Exit_status r) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Ok (t, [], [ `Channel_exit_status (Channel.id c, r) ])
  | Established, Msg_channel_close id ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    let channels = Channel.remove (Channel.id c) t.channels in
    Ok ({ t with channels },
        [ Msg_channel_close (Channel.id c) ;
          Msg_disconnect (DISCONNECT_BY_APPLICATION, "all channels are closed now", "") ],
        [ `Disconnected ])
  | _, _ ->
    debug_msg "unexpected" msg;
    Error "unexpected state and message"

let rec incoming t now buf =
  let buf = Cstruct.append t.linger buf in
  (match t.state with
   | Init _ ->
     Common.version buf >>| fun (msg, buf) ->
     { t with linger = buf }, msg
   | _ ->
     Common.decrypt t.keys_stoc buf >>| fun (keys_stoc, msg, buf) ->
     { t with keys_stoc ; linger = buf }, msg) >>= fun (t, msg) ->
  match msg with
  | None ->
    Printf.printf "no msg\n%!";
    Ok (t, [], [])
  | Some msg ->
    debug_msg "<<<" msg;
    input_msg t msg now >>= fun (t', replies, events) ->
    let t'', replies = output_msgs t' replies in
    incoming t'' now Cstruct.empty >>| fun (t''', replies', events') ->
    t''', replies @ replies', events @ events'

let outgoing_request t ?(id = 0l) ?(want_reply = false) req =
  guard (match t.state with Established -> true | _ -> false) "not yet established" >>= fun () ->
  guard_some (Channel.lookup id t.channels) "no such channel" >>| fun _ ->
  let msg = Ssh.Msg_channel_request (id, want_reply, req) in
  output_msg t msg

let outgoing_data t ?(id = 0l) data =
  guard (match t.state with Established -> true | _ -> false) "not yet established" >>= fun () ->
  guard (Cstruct.len data > 0) "empty data" >>= fun () ->
  guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
  Channel.output_data c data >>| fun (c, frags) ->
  let t' = { t with channels = Channel.update c t.channels } in
  output_msgs t' frags
