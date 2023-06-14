(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
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

let service = "ssh-connection"

let src = Logs.Src.create "awa.client" ~doc:"AWA client"
module Log = (val Logs.src_log src : Logs.LOG)

type event = [
  | `Established of int32
  | `Channel_data of int32 * Cstruct.t
  | `Channel_stderr of int32 * Cstruct.t
  | `Channel_eof of int32
  | `Channel_exit_status of int32 * int32
  | `Disconnected
]

let pp_event ppf = function
  | `Established id -> Format.fprintf ppf "established id %lu" id
  | `Channel_data (id, data) ->
    Format.fprintf ppf "data %lu: %s" id (Cstruct.to_string data)
  | `Channel_stderr (id, data) ->
    Format.fprintf ppf "stderr %lu: %s" id (Cstruct.to_string data)
  | `Channel_eof id -> Format.fprintf ppf "eof %lu" id
  | `Channel_exit_status (id, r) -> Format.fprintf ppf "exit %lu with %lu" id r
  | `Disconnected -> Format.fprintf ppf "disconnected"

type kex_state =
  | Negotiated_kex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * Mirage_crypto_pk.Dh.secret * Ssh.mpint

type ec_secret = [
  | `Ed25519 of Mirage_crypto_ec.X25519.secret
  | `P256 of Mirage_crypto_ec.P256.Dh.secret
  | `P384 of Mirage_crypto_ec.P384.Dh.secret
  | `P521 of Mirage_crypto_ec.P521.Dh.secret
]

type eckex_state =
  | Negotiated_eckex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * ec_secret * Ssh.mpint

type gex_state =
  | Requested_gex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * int32 * int32 * int32
  | Negotiated_gex of string * Ssh.kexinit * string * Ssh.kexinit * Kex.negotiation * int32 * int32 * int32 * Z.t * Z.t * Mirage_crypto_pk.Dh.secret * Ssh.mpint

type userauth_interactive =
  | Requested of string
  | Info_sent

type state =
  | Init of string * Ssh.kexinit
  | Received_version of string * Ssh.kexinit * string
  | Kex of kex_state
  | Eckex of eckex_state
  | Gex of gex_state
  | Newkeys_before_auth of Kex.keys * Kex.keys
  | Requested_service of string
  | Userauth_initial
  | Userauth_password
  | Userauth_publickey of Hostkey.priv
  | Userauth_keyboard_interactive of userauth_interactive
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
  sig_algs : Hostkey.alg list ;
  linger  : Cstruct.t;
  user : string ;
  auth_method : [ `Pubkey of Hostkey.priv | `Password of string ] ;
  authenticator : Keys.authenticator ;
  auth_tried : bool ;
}

let established t = match t.state with Established -> true | _ -> false

let rotate_keys_ctos t new_keys_ctos =
  let open Kex in
  let new_keys_ctos = { new_keys_ctos with seq = t.keys_ctos.seq } in
  { t with keys_ctos = new_keys_ctos }

let rotate_keys_stoc t new_keys_stoc =
  let open Kex in
  let new_keys_stoc = { new_keys_stoc with seq = t.keys_stoc.seq } in
  { t with keys_stoc = new_keys_stoc; keying = false }

let debug_msg prefix = function
  | Ssh.Msg_channel_data (id, data) ->
    Log.debug (fun m -> m "%s (Msg_data %d bytes for %lu)" prefix
                  (Cstruct.length data) id)
  | msg -> Log.debug (fun m -> m "%s %a" prefix Ssh.pp_message msg)

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

let make ?(authenticator = `No_authentication) ~user auth_method =
  let open Ssh in
  let hostkey_algs = match authenticator with
    | `No_authentication -> Hostkey.preferred_algs
    | `Key Hostkey.Rsa_pub _ -> Hostkey.algs_of_typ `Rsa
    | `Key Hostkey.Ed25519_pub _ -> Hostkey.algs_of_typ `Ed25519
    | `Fingerprint (typ, _) -> Hostkey.algs_of_typ typ
  in
  let client_kexinit = Kex.make_kexinit hostkey_algs Kex.client_supported () in
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
            sig_algs = [];
            user ; auth_method ; authenticator ;
            auth_tried = false ;
          }
  in
  output_msgs t [ banner_msg ; kex_msg ]

let handle_kexinit t c_v ckex s_v skex =
  let* neg = Kex.negotiate ~s:skex ~c:ckex in
  Log.info (fun m -> m "negotiated: %a" Kex.pp_negotiation neg);
  (* two cases: directly send the kexdh_init, or RFC 4419 and negotiate group *)
  let state, msg =
    if Kex.is_rfc4419 neg.kex_alg then
      Gex (Requested_gex (c_v, ckex, s_v, skex, neg, Ssh.min_dh, Ssh.n, Ssh.max_dh)),
      Ssh.Msg_kexdh_gex_request (Ssh.min_dh, Ssh.n, Ssh.max_dh)
    else if Kex.is_finite_field neg.kex_alg then
      let secret, my_pub = Kex.Dh.secret_pub neg.kex_alg in
      Kex (Negotiated_kex (c_v, ckex, s_v, skex, neg, secret, my_pub)),
      Ssh.Msg_kexdh_init my_pub
    else (* not RFC 4419, not finite field -> EC *)
      let secret, my_pub = Kex.Dh.ec_secret_pub neg.kex_alg in
      Eckex (Negotiated_eckex (c_v, ckex, s_v, skex, neg, secret, my_pub)),
      Ssh.Msg_kexecdh_init my_pub
  in
  (* this is not correct in respect to the specification (should use
     server-sig-algs extension of 8308): we reuse the server host key algorithms
     from the kex for client key authentication. we iterate over them on
     failure -> eventually we'll use ssh-rsa if the server denies sha256/512 *)
  let sig_algs =
    let s =
      List.fold_left (fun acc a ->
          match Hostkey.alg_of_string a with Ok a -> a :: acc | Error _ -> acc)
        [] skex.server_host_key_algs
    in
    let s = List.filter (fun a -> List.mem a s) Hostkey.preferred_algs in
    match t.auth_method with
    | `Pubkey key -> List.filter Hostkey.(alg_matches (priv_to_typ key)) s
    | `Password _ -> s
  in
  Ok ({ t with state ; sig_algs }, [ msg ], [])

let dh_reply ~ec t now v_c ckex v_s skex neg shared my_pub k_s theirs (alg, signed) =
  let h =
    Kex.Dh.compute_hash ~signed:(not ec) neg
      ~v_c ~v_s ~i_c:(Wire.blob_of_kexinit ckex) ~i_s:skex.Ssh.rawkex
      ~k_s ~e:my_pub ~f:theirs ~k:shared
  in
  if Keys.hostkey_matches t.authenticator k_s && alg = neg.server_host_key_alg && Hostkey.verify alg k_s ~unsigned:h ~signed then begin
    Log.info (fun m -> m "verified kexdh_reply!");
    let session_id = match t.session_id with None -> h | Some x -> x in
    let* new_keys_ctos, new_keys_stoc, key_eol =
      Kex.Dh.derive_keys shared h session_id neg now
    in
    Ok ({ t with
          state = Newkeys_before_auth (new_keys_ctos, new_keys_stoc) ;
          session_id = Some session_id ; key_eol = Some key_eol },
        [ Ssh.Msg_newkeys ], [])
  end else
    Error "couldn't verify kex"

let handle_kexdh_reply t now v_c ckex v_s skex neg secret my_pub k_s theirs p =
  let* shared = Kex.Dh.shared secret theirs in
  dh_reply ~ec:false t now v_c ckex v_s skex neg shared my_pub k_s theirs p

let handle_kexecdh_reply t now v_c ckex v_s skex neg secret my_pub k_s theirs p =
  let* shared = Kex.Dh.ec_shared secret theirs in
  dh_reply ~ec:true t now v_c ckex v_s skex neg shared my_pub k_s theirs p

let handle_kexdh_gex_group t v_c ckex v_s skex neg min n max p gg =
  (* min <= |p| <= max *)
  let open Mirage_crypto_pk.Dh in
  let* group =
    Result.map_error (function `Msg m -> m) (group ~p ~gg ())
  in
  let bits = modulus_size group in
  if Int32.to_int min <= bits && bits <= Int32.to_int max then
    let secret, shared = gen_key group in
    let pub = Mirage_crypto_pk.Z_extra.of_cstruct_be shared in
    let state = Negotiated_gex (v_c, ckex, v_s, skex, neg, min, n, max, p, gg, secret, pub) in
    Ok ({ t with state = Gex state }, [ Ssh.Msg_kexdh_gex_init pub ], [])
  else
    Error "DH group not between min and max"

let handle_kexdh_gex_reply t now v_c ckex v_s skex neg min n max p g secret my_pub k_s theirs (alg, signed) =
  let* shared = Kex.Dh.shared secret theirs in
  let h =
    Kex.Dh.compute_hash_gex neg
      ~v_c ~v_s ~i_c:(Wire.blob_of_kexinit ckex) ~i_s:skex.Ssh.rawkex
      ~k_s ~min ~n ~max ~p ~g ~e:my_pub ~f:theirs ~k:shared
  in
  if Keys.hostkey_matches t.authenticator k_s && alg = neg.server_host_key_alg && Hostkey.verify alg k_s ~unsigned:h ~signed then begin
    Log.info (fun m -> m "verified kexdh_reply!");
    let session_id = match t.session_id with None -> h | Some x -> x in
    let* new_keys_ctos, new_keys_stoc, key_eol =
      Kex.Dh.derive_keys shared h session_id neg now
    in
    Ok ({ t with
          state = Newkeys_before_auth (new_keys_ctos, new_keys_stoc) ;
          session_id = Some session_id ; key_eol = Some key_eol },
        [ Ssh.Msg_newkeys ], [])
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
    Ok ({ t with state = Userauth_initial },
        [ Ssh.Msg_userauth_request (t.user, service, Authnone) ],
        [])
  | service -> Error ("unknown service: " ^ service)

let handle_auth_none t = function
  | [] -> Error "no authentication method left"
  | xs ->
    if t.auth_tried then
      Error "authentication failure"
    else
      let auth_req met = [ Ssh.Msg_userauth_request (t.user, service, met) ] in
      match t.auth_method with
      | `Pubkey key ->
        if List.mem "publickey" xs then
          let pub = Hostkey.pub_of_priv key in
          let met = Ssh.Pubkey (pub, None) in
          Ok ({ t with state = Userauth_publickey key ; auth_tried = true },
              auth_req met, [])
        else
          Error "no supported authentication methods left"
      | `Password pass ->
        if List.mem "password" xs then
          let met = Ssh.Password (pass, None) in
          Ok ({ t with state = Userauth_password ; auth_tried = true },
              auth_req met, [])
        else if List.mem "keyboard-interactive" xs then
          let met = Ssh.Keyboard_interactive (None, []) in
          let state = Userauth_keyboard_interactive (Requested pass) in
          Ok ({ t with state ; auth_tried = true }, auth_req met, [])
        else
          Error "no supported authentication methods left"

let handle_pk_auth t key =
  let session_id = match t.session_id with None -> assert false | Some x -> x in
  let* alg, sig_algs =
    match t.sig_algs with
    | [] -> Error "no more signature algorithms available"
    | a :: rt -> Ok (a, rt)
  in
  let signed = Auth.sign t.user alg key session_id service in
  let met = Ssh.Pubkey (Hostkey.pub_of_priv key, Some (alg, signed)) in
  Ok ({ t with state = Userauth_publickey key ; sig_algs },
      [ Ssh.Msg_userauth_request (t.user, service, met) ],
      [])

let handle_userauth_info_req t password (name, instruction, lang, prompts) =
  Log.info (fun m -> m "keyboard interactive: name %s instruction %s lang %s"
               name instruction lang);
  List.iter (fun (prompt, _echo) -> Log.info (fun m -> m "PROMPT: %s" prompt))
    prompts;
  match prompts with
  | [ _ ] ->
    Ok ({ t with state = Userauth_keyboard_interactive Info_sent },
        [ Ssh.Msg_userauth_info_response [ password ] ], [])
  | _ -> Error "keyboard interactive user authentication: not a single prompt"

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

let channel_data t id data =
  let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
  let* c, data, adjust = Channel.input_data c data in
  let channels = Channel.update c t.channels in
  let out = match adjust with None -> [] | Some e -> [ e ] in
  Ok ({ t with channels }, out, Channel.id c, data)

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
      let* m = Wire.dh_kexdh_of_kex i d in
      match m with
      | Msg_kexdh_reply (pub, theirs, signed) ->
        handle_kexdh_reply t now cv ckex sv skex neg sec mypub pub theirs signed
      | _ ->
        Error "unexpected KEX message"
    end
  | Eckex (Negotiated_eckex (cv, ckex, sv, skex, neg, sec, mypub)),
    Msg_kex (i, d) ->
    begin
      let* m = Wire.dh_kexecdh_of_kex i d in
      match m with
      | Msg_kexecdh_reply (pub, theirs, signed) ->
        handle_kexecdh_reply t now cv ckex sv skex neg sec mypub pub theirs signed
      | _ ->
        Error "unexpected KEX message"
    end
  | Gex sub, Msg_kex (i, d) ->
    begin
      let* msg = Wire.dh_kexdh_gex_of_kex i d in
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
  | Userauth_initial, Msg_userauth_failure (methods, _) ->
    handle_auth_none t methods
  | Userauth_publickey key, Msg_userauth_failure _ ->
    (* signature algorithm wasn't received well by the server *)
    handle_pk_auth t key
  | Userauth_publickey key, Msg_userauth_1 buf ->
    begin
      let* m = Wire.userauth_pk_ok buf in
      match m with
      | Msg_userauth_pk_ok pub ->
        if Hostkey.pub_of_priv key = pub then
          handle_pk_auth t key
        else
          Error "key user authentication: public key does not match private"
      | _ -> Error "unexpected userauth message"
    end
  | Userauth_keyboard_interactive (Requested password), Msg_userauth_1 buf ->
    begin
      let* m = Wire.userauth_info_request buf in
      match m with
      | Msg_userauth_info_request (n, i, l, p) ->
        handle_userauth_info_req t password (n, i, l, p)
      | _ -> Error "unexpected userauth message"
    end
  | Userauth_keyboard_interactive Info_sent, Msg_userauth_1 buf ->
    begin
      (* in contrast to 4256, OpenSSH sends another Info_req with no prompts *)
      let* m = Wire.userauth_info_request buf in
      match m with
      | Msg_userauth_info_request (_, _, _, []) ->
        Ok (t, [ Ssh.Msg_userauth_info_response [] ], [])
      | _ -> Error "unexpected userauth message"
    end
  | (Userauth_password | Userauth_publickey _ | Userauth_keyboard_interactive _), Msg_userauth_success ->
    open_channel t
  | (Userauth_password | Userauth_publickey _ | Userauth_keyboard_interactive _), Msg_userauth_banner (banner, lang) ->
    Log.info (fun m -> m "userauth banner %s%s" banner
                 (if lang = "" then "" else " (lang " ^ lang ^ ")"));
    Ok (t, [], [])
  | (Userauth_password | Userauth_keyboard_interactive _), Msg_userauth_failure _ ->
    Error "user authentication failed"
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
    let* t, out, id, data = channel_data t id data in
    Ok (t, out, [ `Channel_data (id, data) ])
  | Established, Msg_channel_extended_data (id, 1l, data) ->
    let* t, out, id, data = channel_data t id data in
    Ok (t, out, [ `Channel_stderr (id, data) ])
  | Established, Msg_channel_window_adjust (id, len) ->
    let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
    let* c, msgs = Channel.adjust_window c len in
    let channels = Channel.update c t.channels in
    Ok ({ t with channels }, msgs, [])
  | Established, Msg_channel_eof id ->
    let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
    Ok (t, [], [ `Channel_eof (Channel.id c) ])
  | Established, Msg_channel_request (id, false, Exit_status r) ->
    let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
    Ok (t, [], [ `Channel_exit_status (Channel.id c, r) ])
  | Established, Msg_channel_success id ->
    let* _c = guard_some (Channel.lookup id t.channels) "no such channel" in
    Log.info (fun m -> m "channel success %lu" id);
    Ok (t, [], [])
  | Established, Msg_channel_close id ->
    let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
    let channels = Channel.remove (Channel.id c) t.channels in
    let msg = "all the channels are closed now, nothing left to do here" in
    Ok ({ t with channels },
        [ Msg_channel_close (Channel.id c) ;
          Msg_disconnect (DISCONNECT_BY_APPLICATION, msg, "") ],
        [ `Disconnected ])
  | _, Msg_disconnect (code, msg, lang) ->
    Log.err (fun m -> m "disconnected: %s %s%s"
                (Ssh.disconnect_code_to_string code)
                msg (if lang = "" then "" else "(lang " ^ lang ^ ")"));
    Error "disconnected"
  | _, _ ->
    debug_msg "unexpected" msg;
    Error "unexpected state and message"

let rec incoming t now buf =
  let buf = Cstruct.append t.linger buf in
  let* t, msg =
    match t.state with
    | Init _ ->
      let* msg, buf = Common.version buf in
      Ok ({ t with linger = buf }, msg)
    | _ ->
      let* keys_stoc, msg, buf = Common.decrypt t.keys_stoc buf in
      Ok ({ t with keys_stoc ; linger = buf }, msg)
  in
  match msg with
  | None -> Ok (t, [], [])
  | Some msg ->
    debug_msg "<<<" msg;
    let* t', replies, events = input_msg t msg now in
    let t'', replies = output_msgs t' replies in
    let* t''', replies', events' = incoming t'' now Cstruct.empty in
    Ok (t''', replies @ replies', events @ events')

let outgoing_request t ?(id = 0l) ?(want_reply = false) req =
  let* () = guard (established t) "not yet established" in
  let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
  let msg = Ssh.Msg_channel_request (c.them.id, want_reply, req) in
  Ok (output_msg t msg)

let outgoing_data t ?(id = 0l) data =
  let* () = guard (established t) "not yet established" in
  let* () = guard (Cstruct.length data > 0) "empty data" in
  let* c = guard_some (Channel.lookup id t.channels) "no such channel" in
  let* c, frags = Channel.output_data c data in
  let t' = { t with channels = Channel.update c t.channels } in
  Ok (output_msgs t' frags)
