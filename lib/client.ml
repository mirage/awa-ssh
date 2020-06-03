(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed!
*)

open Rresult.R
open Util

let service = "ssh-connection"

let src = Logs.Src.create "awa.client" ~doc:"AWA client"
module Log = (val Logs.src_log src : Logs.LOG)

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

type kex_state =
  | Negotiated_kex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * Mirage_crypto_pk.Dh.secret * Ssh.mpint

type gex_state =
  | Requested_gex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * int32 * int32 * int32
  | Negotiated_gex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * int32 * int32 * int32 * Z.t * Z.t * Mirage_crypto_pk.Dh.secret * Ssh.mpint

type state =
  | Init of string * Ssh.kexinit
  | Received_version of string * Ssh.kexinit * string
  | Kex of kex_state
  | Gex of gex_state
  | Newkeys_before_auth of Kex.keys * Kex.keys
  | Requested_service of string
  | Userauth_request of Ssh.auth_method
  | Userauth_requested
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
  user : string ;
  key : Hostkey.priv ;
  authenticator : Keys.authenticator ;
}

let established t = match t.state with Established -> true | _ -> false

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
    Log.debug (fun m -> m "%s (Msg_data %d bytes for %lu)" prefix
                  (Cstruct.len data) id)
  | msg -> Log.debug (fun m -> m "%s %s" prefix (Ssh.message_to_string msg))

let output_msg t msg =
  let buf, keys_ctos = Common.output_msg t.keys_ctos msg in
  let t = { t with keys_ctos } in
  debug_msg ">>>" msg;
  (* Do state transitions *)
  match t.state with
  | Newkeys_before_auth (my_keys, _) ->
    Log.debug (fun m -> m "rotating ctos keys");
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

let make ?(authenticator = `No_authentication) ~user key =
  let open Ssh in
  let client_kexinit = Kex.make_kexinit Kex.client_supported () in
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
            user ; key ; authenticator
          }
  in
  output_msgs t [ banner_msg ; kex_msg ]

let handle_kexinit t c_v ckex s_v skex =
  Kex.negotiate ~s:skex ~c:ckex >>= fun neg ->
  (* two cases: directly send the kexdh_init, or RFC 4419 and negotiate group *)
  let state, msg =
    if Kex.is_rfc4419 neg.kex_alg then
      Gex (Requested_gex (c_v, ckex, s_v, skex, neg, Ssh.min_dh, Ssh.n, Ssh.max_dh)),
      Ssh.Msg_kexdh_gex_request (Ssh.min_dh, Ssh.n, Ssh.max_dh)
    else
      let secret, my_pub = Kex.Dh.secret_pub neg.kex_alg in
      Kex (Negotiated_kex (c_v, ckex, s_v, skex, neg, secret, my_pub)),
      Ssh.Msg_kexdh_init my_pub
  in
  ok ({ t with state }, [ msg ], [])

let handle_kexdh_reply t now v_c ckex v_s skex neg secret my_pub k_s theirs (alg, signed) =
  Kex.Dh.shared secret theirs >>= fun shared ->
  let h =
    Kex.Dh.compute_hash neg
      ~v_c ~v_s ~i_c:(Wire.blob_of_kexinit ckex) ~i_s:skex.Ssh.rawkex
      ~k_s ~e:my_pub ~f:theirs ~k:shared
  in
  if Keys.hostkey_matches t.authenticator k_s && alg = neg.server_host_key_alg && Hostkey.verify alg k_s ~unsigned:h ~signed then begin
    Log.info (fun m -> m "verified kexdh_reply!");
    let session_id = match t.session_id with None -> h | Some x -> x in
    Kex.Dh.derive_keys shared h session_id neg now
    >>| fun (new_keys_ctos, new_keys_stoc, key_eol) ->
    { t with
      state = Newkeys_before_auth (new_keys_ctos, new_keys_stoc) ;
      session_id = Some session_id ; key_eol = Some key_eol },
    [ Ssh.Msg_newkeys ], []
  end else
    Error "couldn't verify kex"

let handle_kexdh_gex_group t v_c ckex v_s skex neg min n max p gg =
  (* min <= |p| <= max *)
  let open Mirage_crypto_pk.Dh in
  reword_error (function `Msg m -> m) (group ~p ~gg ()) >>= fun group ->
  let bits = modulus_size group in
  if Int32.to_int min <= bits && bits <= Int32.to_int max then
    let secret, shared = gen_key group in
    let pub = Mirage_crypto_pk.Z_extra.of_cstruct_be shared in
    let state = Negotiated_gex (v_c, ckex, v_s, skex, neg, min, n, max, p, gg, secret, pub) in
    Ok ({ t with state = Gex state }, [ Ssh.Msg_kexdh_gex_init pub ], [])
  else
    Error "DH group not between min and max"

let handle_kexdh_gex_reply t now v_c ckex v_s skex neg min n max p g secret my_pub k_s theirs (alg, signed) =
  Kex.Dh.shared secret theirs >>= fun shared ->
  let h =
    Kex.Dh.compute_hash_gex neg
      ~v_c ~v_s ~i_c:(Wire.blob_of_kexinit ckex) ~i_s:skex.Ssh.rawkex
      ~k_s ~min ~n ~max ~p ~g ~e:my_pub ~f:theirs ~k:shared
  in
  if Keys.hostkey_matches t.authenticator k_s && alg = neg.server_host_key_alg && Hostkey.verify alg k_s ~unsigned:h ~signed then begin
    Log.info (fun m -> m "verified kexdh_reply!");
    let session_id = match t.session_id with None -> h | Some x -> x in
    Kex.Dh.derive_keys shared h session_id neg now
    >>| fun (new_keys_ctos, new_keys_stoc, key_eol) ->
    { t with
      state = Newkeys_before_auth (new_keys_ctos, new_keys_stoc) ;
      session_id = Some session_id ; key_eol = Some key_eol },
    [ Ssh.Msg_newkeys ], []
  end else
    Error "couldn't verify kex"

let handle_newkeys_before_auth t keys =
  Log.debug (fun m -> m "rotating stoc keys");
  let t' = rotate_keys_stoc t keys in
  let service = "ssh-userauth" in
  Ok ({ t' with state = Requested_service service },
      [ Ssh.Msg_service_request service ], [])

let service_accepted t = function
  | "ssh-userauth" ->
    Ok ({ t with state = Userauth_request Authnone },
        [ Ssh.Msg_userauth_request (t.user, service, Authnone) ],
        [])
  | service -> Error ("unknown service: " ^ service)

let handle_auth_failure t _ = function
  | [] -> Error "no authentication method left"
  | xs when List.mem "publickey" xs ->
    let pub = Hostkey.pub_of_priv t.key in
    let met = Ssh.Pubkey (pub, None) in
    Ok ({ t with state = Userauth_request met },
        [ Ssh.Msg_userauth_request (t.user, service, met) ],
        [])
  | _ -> Error "no supported authentication methods left"

let handle_pk_ok t m pk = match m with
  | Ssh.Pubkey (pub, None) when pub = pk ->
    let session_id = match t.session_id with None -> assert false | Some x -> x in
    (* TODO figure out which to use from extensions, RFC 8308 *)
    let alg = Hostkey.Rsa_sha1 in
    let signed = Auth.sign t.user alg t.key session_id service in
    let met = Ssh.Pubkey (Hostkey.pub_of_priv t.key, Some (alg, signed)) in
    Ok ({ t with state = Userauth_requested },
        [ Ssh.Msg_userauth_request (t.user, service, met) ],
        [])
  | _ -> Error "not sure how we ended in pk ok now"

let open_channel t =
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
  | Init (cv, ckex), Msg_version v ->
    Ok ({ t with state = Received_version (cv, ckex, v) }, [], [])
  | Received_version (cv, ckex, sv), Msg_kexinit skex ->
    handle_kexinit t cv ckex sv skex
  | Kex (Negotiated_kex (cv, ckex, sv, skex, neg, sec, mypub)),
    Msg_kex (i, d) ->
    begin
      Wire.dh_kexdh_of_kex i d >>= function
      | Msg_kexdh_reply (pub, theirs, signed) ->
        handle_kexdh_reply t now cv ckex sv skex neg sec mypub pub theirs signed
      | _ ->
        Error "unexpected KEX message"
    end
  | Gex sub, Msg_kex (i, d) ->
    begin
      Wire.dh_kexdh_gex_of_kex i d >>= fun msg ->
      match sub, msg with
      | Requested_gex (cv, ckex, sv, skex, neg, min, n, max),
        Msg_kexdh_gex_group (p, g) ->
        handle_kexdh_gex_group t cv ckex sv skex neg min n max p g
      | Negotiated_gex (cv, ckex, sv, skex, neg, min, n, max, p, g, sec, mypub),
        Msg_kexdh_gex_reply (pub, theirs, signed) ->
        handle_kexdh_gex_reply t now cv ckex sv skex neg min n max p g sec mypub pub theirs signed
      | _ ->
        Error "unexpected KEX message"
    end
  | Newkeys_before_auth (_, keys), Msg_newkeys ->
    handle_newkeys_before_auth t keys
  | Requested_service s, Msg_service_accept s' when s = s' ->
    service_accepted t s
  | Userauth_request m, Msg_userauth_failure (methods, _) ->
    handle_auth_failure t m methods
  | Userauth_request m, Msg_userauth_pk_ok pk -> handle_pk_ok t m pk
  | Userauth_request _, Msg_userauth_success -> open_channel t
  | Userauth_requested, Msg_userauth_success -> open_channel t
  | Opening_channel us, Msg_channel_open_confirmation (oid, tid, win, max, data) ->
    open_channel_success t us oid tid win max data
  | _, Msg_global_request (_, want_reply, Unknown_request _) ->
    Log.info (fun m -> m "ignoring unknown global request (want reply %B)"
                 want_reply);
    Ok (t, [], [])
  | _, Msg_debug (_, msg, lang) ->
    Log.info (fun m -> m "ignoring debug %s (lang %s)" msg lang);
    Ok (t, [], [])
  | Established, Msg_channel_data (id, data) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Channel.input_data c data >>| fun (c, data, adjust) ->
    let channels = Channel.update c t.channels in
    let out = match adjust with None -> [] | Some e -> [ e ] in
    { t with channels }, out, [ `Channel_data (Channel.id c, data) ]
  | Established, Msg_channel_window_adjust (id, len) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
    Channel.adjust_window c len >>| fun (c, msgs) ->
    let channels = Channel.update c t.channels in
    { t with channels }, msgs, []
  | Established, Msg_channel_eof id ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>| fun c ->
    t, [], [ `Channel_eof (Channel.id c) ]
  | Established, Msg_channel_request (id, false, Exit_status r) ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>| fun c ->
    t, [], [ `Channel_exit_status (Channel.id c, r) ]
  | Established, Msg_channel_success id ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>| fun _c ->
    Log.info (fun m -> m "channel success %lu" id);
    t, [], []
  | Established, Msg_channel_close id ->
    guard_some (Channel.lookup id t.channels) "no such channel" >>| fun c ->
    let channels = Channel.remove (Channel.id c) t.channels in
    let msg = "all the channels are closed now, nothing left to do here" in
    { t with channels },
    [ Msg_channel_close (Channel.id c) ;
      Msg_disconnect (DISCONNECT_BY_APPLICATION, msg, "") ],
    [ `Disconnected ]
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
  | None -> Ok (t, [], [])
  | Some msg ->
    debug_msg "<<<" msg;
    input_msg t msg now >>= fun (t', replies, events) ->
    let t'', replies = output_msgs t' replies in
    incoming t'' now Cstruct.empty >>| fun (t''', replies', events') ->
    t''', replies @ replies', events @ events'

let outgoing_request t ?(id = 0l) ?(want_reply = false) req =
  guard (established t) "not yet established" >>= fun () ->
  guard_some (Channel.lookup id t.channels) "no such channel" >>| fun c ->
  let msg = Ssh.Msg_channel_request (c.them.id, want_reply, req) in
  output_msg t msg

let outgoing_data t ?(id = 0l) data =
  guard (established t) "not yet established" >>= fun () ->
  guard (Cstruct.len data > 0) "empty data" >>= fun () ->
  guard_some (Channel.lookup id t.channels) "no such channel" >>= fun c ->
  Channel.output_data c data >>| fun (c, frags) ->
  let t' = { t with channels = Channel.update c t.channels } in
  output_msgs t' frags
