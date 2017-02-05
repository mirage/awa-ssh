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

[%%cstruct
type pkt_hdr = {
  pkt_len: uint32_t;
  pad_len: uint8_t;
} [@@big_endian]]

let max_pkt_len = Int32.of_int 64000    (* 64KB should be enough *)

let scan_version buf =
  let s = Cstruct.to_string buf in
  let len = String.length s in
  let not_found =
    if len < (1024 * 64) then
      ok None
    else
      error "Buffer is too big"
  in
  let rec scan start off =
    if off = len then
      not_found
    else
      match (String.get s (pred off), String.get s off) with
      | ('\r', '\n') ->
        let line = String.sub s start (off - start - 1) in
        let line_len = String.length line in
        if line_len < 4 ||
           String.sub line 0 4 <> "SSH-" then
          scan (succ off) (succ off)
        else if (line_len < 9) then
          error "Version line is too short"
        else
          let tokens = Str.split_delim (Str.regexp "-") line in
          if List.length tokens <> 3 then
            error "Can't parse version line"
          else
            let version = List.nth tokens 1 in
            let peer_version = List.nth tokens 2 in
            if version <> "2.0" then
              error ("Bad version " ^ version)
            else
              safe_shift buf (succ off) >>= fun buf ->
              ok (Some (buf, peer_version))
      | _ -> scan start (succ off)
  in
  if len < 2 then
    not_found
  else
    scan 0 1

let scan_pkt buf =
  let len = Cstruct.len buf in
  let partial () =
    if len < (1024 * 64) then
      ok None
    else
      error "Buffer is too big"
  in
  if len < 4 then
    partial ()
  else
    let pkt_len32 = get_pkt_hdr_pkt_len buf in
    let pkt_len = Int32.to_int pkt_len32 in
    let pad_len = get_pkt_hdr_pad_len buf in
    (* XXX remember mac_len *)
    guard
      (pkt_len <> 0 &&
       ((u32_compare pkt_len32 max_pkt_len) < 0) &&
       (pkt_len > pad_len + 1))
      "Malformed packet"
    >>= fun () ->
    assert (len > 4);
    if pkt_len > (len - 4) then
      partial ()
    else
      let payload_len = pkt_len - pad_len - 1 in
      let clen =
        4 +                (* pkt_len field itself *)
        pkt_len +          (* size of this packet  *)
        pad_len            (* padding after packet *)
                           (* XXX mac_len missing !*)
      in
      safe_sub buf sizeof_pkt_hdr payload_len >>= fun pkt ->
      ok (Some (pkt, clen))

[%%cenum
type message_id =
  | SSH_MSG_DISCONNECT                [@id 1]
  | SSH_MSG_IGNORE                    [@id 2]
  | SSH_MSG_UNIMPLEMENTED             [@id 3]
  | SSH_MSG_DEBUG                     [@id 4]
  | SSH_MSG_SERVICE_REQUEST           [@id 5]
  | SSH_MSG_SERVICE_ACCEPT            [@id 6]
  | SSH_MSG_KEXINIT                   [@id 20]
  | SSH_MSG_NEWKEYS                   [@id 21]
  | SSH_MSG_KEXDH_INIT                [@id 30]
  | SSH_MSG_KEXDH_REPLY               [@id 31]
  | SSH_MSG_USERAUTH_REQUEST          [@id 50]
  | SSH_MSG_USERAUTH_FAILURE          [@id 51]
  | SSH_MSG_USERAUTH_SUCCESS          [@id 52]
  | SSH_MSG_USERAUTH_BANNER           [@id 53]
  | SSH_MSG_GLOBAL_REQUEST            [@id 80]
  | SSH_MSG_REQUEST_SUCCESS           [@id 81]
  | SSH_MSG_REQUEST_FAILURE           [@id 82]
  | SSH_MSG_CHANNEL_OPEN              [@id 90]
  | SSH_MSG_CHANNEL_OPEN_CONFIRMATION [@id 91]
  | SSH_MSG_CHANNEL_OPEN_FAILURE      [@id 92]
  | SSH_MSG_CHANNEL_WINDOW_ADJUST     [@id 93]
  | SSH_MSG_CHANNEL_DATA              [@id 94]
  | SSH_MSG_CHANNEL_EXTENDED_DATA     [@id 95]
  | SSH_MSG_CHANNEL_EOF               [@id 96]
  | SSH_MSG_CHANNEL_CLOSE             [@id 97]
  | SSH_MSG_CHANNEL_REQUEST           [@id 98]
  | SSH_MSG_CHANNEL_SUCCESS           [@id 99]
  | SSH_MSG_CHANNEL_FAILURE           [@id 100]
[@@uint8_t][@@sexp]]

let decode_message_id buf =
  trap_error (fun () ->
      let id = (Cstruct.get_uint8 buf 0) in
      match int_to_message_id id with
      | None -> invalid_arg (Printf.sprintf "Unknown message id %d" id)
      | Some msgid -> msgid, (Cstruct.shift buf 1)) ()

let encode_message_id m =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 (message_id_to_int m);
  buf

let decode_string buf =
  (* XXX bad to_int conversion *)
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      (Cstruct.copy buf 4 len), Cstruct.shift buf (len + 4)) ()

let encode_string s =
  let len = String.length s in
  if len > 255 then
      invalid_arg "String is too long";
  let buf = Cstruct.create (len + 4) in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int len);
  Cstruct.blit_from_string s 0 buf 4 len;
  buf

let decode_cstring buf =
  (* XXX bad to_int conversion *)
  trap_error (fun () ->
      let len = Cstruct.BE.get_uint32 buf 0 |> Int32.to_int in
      (Cstruct.set_len (Cstruct.shift buf 4) len,
       Cstruct.shift buf (len + 4))) ()

let encode_cstring c =
  trap_error (fun () ->
      let len = Cstruct.len c in
      if len > 255 then
        invalid_arg "Cstruct string is too long";
      let buf = Cstruct.create (len + 4) in
      Cstruct.BE.set_uint32 buf 0 (Int32.of_int len);
      Cstruct.blit c 0 buf 4 len;
      buf) ()

let decode_mpint buf =
  trap_error (fun () ->
      let rec strip_zeros buf =
        if (Cstruct.get_uint8 buf 0) <> 0 then
          buf
        else
          strip_zeros (Cstruct.shift buf 1)
      in
      match ((Cstruct.BE.get_uint32 buf 0) |> Int32.to_int) with
      | 0 -> (Cstruct.create 0, buf)
      | len ->
        let mpbuf = Cstruct.sub buf 4 len in
        let msb = Cstruct.get_uint8 mpbuf 0 in
        if (msb land 0x80) <> 0 then
          invalid_arg "Negative mpint"
        else
          strip_zeros mpbuf, Cstruct.shift buf (len + 4)) ()

let encode_mpint mpint =
  let len = Cstruct.len mpint in
  if len > 0 &&
     ((Cstruct.get_uint8 mpint 0) land 0x80) <> 0 then
    let head = Cstruct.create 5 in
    Cstruct.set_uint8 head 4 0;
    Cstruct.BE.set_uint32 head 0 (Int32.of_int (succ len));
    Cstruct.append head mpint
  else
    let head = Cstruct.create 4 in
    Cstruct.BE.set_uint32 head 0 (Int32.of_int len);
    Cstruct.append head mpint

let encode_rsa (rsa : Nocrypto.Rsa.pub) =
  let open Nocrypto in
  let s = encode_string "ssh-rsa" in
  let e = encode_mpint (Numeric.Z.to_cstruct_be rsa.Rsa.e) in
  let n = encode_mpint (Numeric.Z.to_cstruct_be rsa.Rsa.n) in
  Cstruct.concat [s; e; n]

let decode_uint32 buf =
  trap_error (fun () ->
      Cstruct.BE.get_uint32 buf 0, Cstruct.shift buf 4) ()

let encode_uint32 v =
  let buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 buf 0 v;
  buf

let decode_bool buf =
  trap_error (fun () ->
      (Cstruct.get_uint8 buf 0) <> 0, Cstruct.shift buf 1) ()

let encode_bool b =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 (if b then 1 else 0);
  buf

let encode_nl nl =
  encode_string (String.concat "," nl)

let decode_nl buf =
  decode_string buf >>= fun (s, buf) ->
  ok ((Str.split (Str.regexp ",") s), buf)

let encode_disconnect code desc lang =
  let code = encode_uint32 code in
  let desc = encode_string desc in
  let lang = encode_string lang in
  Cstruct.concat [encode_message_id SSH_MSG_KEXINIT; code; desc; lang]

type kex_pkt = {
  cookie : Cstruct.t;
  kex_algorithms : string list;
  server_host_key_algorithms : string list;
  encryption_algorithms_ctos : string list;
  encryption_algorithms_stoc : string list;
  mac_algorithms_ctos : string list;
  mac_algorithms_stoc : string list;
  compression_algorithms_ctos : string list;
  compression_algorithms_stoc : string list;
  languages_ctos : string list;
  languages_stoc : string list;
  first_kex_packet_follows : bool
} [@@deriving sexp]

type kex_neg = {
  kex_algorithm : string;
  server_host_key_algorithm : string;
  encryption_algorithm_ctos : string;
  encryption_algorithm_stoc : string;
  mac_algorithm_ctos : string;
  mac_algorithm_stoc : string;
  compression_algorithm_ctos : string;
  compression_algorithm_stoc : string;
  language_ctos : string;
  language_stoc : string;
}

let negotiate_kex ~s ~c =
  let pick_common ~s ~c e =
    try
      Ok (List.find (fun x -> List.mem x s) c)
    with
      Not_found -> Error e
  in
  pick_common
    ~s:s.kex_algorithms
    ~c:c.kex_algorithms
    "Can't agree on kex algorithm"
  >>= fun kex_algorithm ->
  pick_common
    ~s:s.server_host_key_algorithms
    ~c:c.server_host_key_algorithms
    "Can't agree on server host key algorithm"
  >>= fun server_host_key_algorithm ->
  pick_common
    ~s:s.encryption_algorithms_ctos
    ~c:c.encryption_algorithms_ctos
    "Can't agree on encryption algorithm client to server"
  >>= fun encryption_algorithm_ctos ->
  pick_common
    ~s:s.encryption_algorithms_stoc
    ~c:c.encryption_algorithms_stoc
    "Can't agree on encryption algorithm server to client"
  >>= fun encryption_algorithm_stoc ->
  pick_common
    ~s:s.mac_algorithms_ctos
    ~c:c.mac_algorithms_ctos
    "Can't agree on mac algorithm client to server"
  >>= fun mac_algorithm_ctos ->
  pick_common
    ~s:s.mac_algorithms_stoc
    ~c:c.mac_algorithms_stoc
    "Can't agree on mac algorithm server to client"
  >>= fun mac_algorithm_stoc ->
  pick_common
    ~s:s.compression_algorithms_ctos
    ~c:c.compression_algorithms_ctos
    "Can't agree on compression algorithm client to server"
  >>= fun compression_algorithm_ctos ->
  pick_common
    ~s:s.compression_algorithms_stoc
    ~c:c.compression_algorithms_stoc
    "Can't agree on compression algorithm server to client"
  >>= fun compression_algorithm_stoc ->
  ok {
    kex_algorithm;
    server_host_key_algorithm;
    encryption_algorithm_ctos;
    encryption_algorithm_stoc;
    mac_algorithm_ctos;
    mac_algorithm_stoc;
    compression_algorithm_ctos;
    compression_algorithm_stoc;
    language_ctos = "";         (* XXX *)
    language_stoc = "";         (* XXX *)
  }

let make_kex () =
  { cookie = Nocrypto.Rng.generate 16;
    kex_algorithms = [ "diffie-hellman-group14-sha1";
                       "diffie-hellman-group1-sha1" ];
    server_host_key_algorithms = [ "ssh-rsa" ];
    encryption_algorithms_ctos = [ "aes128-ctr" ];
    encryption_algorithms_stoc = [ "aes128-ctr" ];
    mac_algorithms_ctos = [ "hmac-sha1" ];
    mac_algorithms_stoc = [ "hmac-sha1" ];
    compression_algorithms_ctos = [ "none" ];
    compression_algorithms_stoc = [ "none" ];
    languages_ctos = [];
    languages_stoc = [];
    first_kex_packet_follows = false }

let encode_kex kex =
  let f = encode_nl in
  let nll = Cstruct.concat
      [ f kex.kex_algorithms;
        f kex.server_host_key_algorithms;
        f kex.encryption_algorithms_ctos;
        f kex.encryption_algorithms_stoc;
        f kex.mac_algorithms_ctos;
        f kex.mac_algorithms_stoc;
        f kex.compression_algorithms_ctos;
        f kex.compression_algorithms_stoc;
        f kex.languages_ctos;
        f kex.languages_stoc; ]
  in
  let head = encode_message_id SSH_MSG_KEXINIT in
  let tail = Cstruct.create 5 in  (* first_kex_packet_follows + reserved *)
  Cstruct.set_uint8 tail 0 (if kex.first_kex_packet_follows then 1 else 0);
  Cstruct.BE.set_uint32 tail 1 Int32.zero;
  Cstruct.concat [head; kex.cookie; nll; tail]

let encode_userauth_failure nl psucc =
  let head = encode_message_id SSH_MSG_USERAUTH_FAILURE in
  Cstruct.concat [head; encode_nl nl; encode_bool psucc]

type message =
  | Ssh_msg_disconnect of (int32 * string * string)
  | Ssh_msg_ignore of string
  | Ssh_msg_unimplemented of int32
  | Ssh_msg_debug of (bool * string * string)
  | Ssh_msg_service_request of string
  | Ssh_msg_service_accept of string
  | Ssh_msg_kexinit of kex_pkt
  | Ssh_msg_kexdh_init of Cstruct.t
  | Ssh_msg_kexdh_reply of (Cstruct.t * Cstruct.t * Cstruct.t)
  | Ssh_msg_newkeys
  | Ssh_msg_userauth_request
  | Ssh_msg_userauth_failure of (string list * bool)
  | Ssh_msg_userauth_success
  | Ssh_msg_userauth_banner of (string * string)
  | Ssh_msg_global_request
  | Ssh_msg_request_success
  | Ssh_msg_request_failure
  | Ssh_msg_channel_open
  | Ssh_msg_channel_open_confirmation
  | Ssh_msg_channel_open_failure
  | Ssh_msg_channel_window_adjust
  | Ssh_msg_channel_data
  | Ssh_msg_channel_extended_data
  | Ssh_msg_channel_eof
  | Ssh_msg_channel_close
  | Ssh_msg_channel_request
  | Ssh_msg_channel_success
  | Ssh_msg_channel_failure

let message_of_buf buf =
  decode_message_id buf >>= fun (msgid, buf) ->
  let unimplemented () =
    error (Printf.sprintf "Message %d unimplemented" (message_id_to_int msgid))
  in
  match msgid with
  | SSH_MSG_DISCONNECT ->
    decode_uint32 buf >>= fun (code, buf) ->
    decode_string buf >>= fun (desc, buf) ->
    decode_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_disconnect (code, desc, lang))
  | SSH_MSG_IGNORE ->
    decode_string buf >>= fun (x, buf) ->
    ok (Ssh_msg_ignore x)
  | SSH_MSG_UNIMPLEMENTED ->
    decode_uint32 buf >>= fun (x, buf) ->
    ok (Ssh_msg_unimplemented x)
  | SSH_MSG_DEBUG ->
    decode_bool buf >>= fun (always_display, buf) ->
    decode_string buf >>= fun (message, buf) ->
    decode_string buf >>= fun (lang, buf) ->
    ok (Ssh_msg_debug (always_display, message, lang))
  | SSH_MSG_SERVICE_REQUEST ->
    decode_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_request x)
  | SSH_MSG_SERVICE_ACCEPT ->
    decode_string buf >>= fun (x, buf) -> ok (Ssh_msg_service_accept x)
  | SSH_MSG_KEXINIT ->
    (* Jump over cookie *)
    let cookiebegin = buf in
    safe_shift buf 16 >>= fun buf ->
    decode_nl buf >>= fun (kex_algorithms, buf) ->
    decode_nl buf >>= fun (server_host_key_algorithms, buf) ->
    decode_nl buf >>= fun (encryption_algorithms_ctos, buf) ->
    decode_nl buf >>= fun (encryption_algorithms_stoc, buf) ->
    decode_nl buf >>= fun (mac_algorithms_ctos, buf) ->
    decode_nl buf >>= fun (mac_algorithms_stoc, buf) ->
    decode_nl buf >>= fun (compression_algorithms_ctos, buf) ->
    decode_nl buf >>= fun (compression_algorithms_stoc, buf) ->
    decode_nl buf >>= fun (languages_ctos, buf) ->
    decode_nl buf >>= fun (languages_stoc, buf) ->
    decode_bool buf >>= fun (first_kex_packet_follows, buf) ->
    ok (Ssh_msg_kexinit
          { cookie = Cstruct.set_len cookiebegin 16;
            kex_algorithms;
            server_host_key_algorithms;
            encryption_algorithms_ctos;
            encryption_algorithms_stoc;
            mac_algorithms_ctos;
            mac_algorithms_stoc;
            compression_algorithms_ctos;
            compression_algorithms_stoc;
            languages_ctos;
            languages_stoc;
            first_kex_packet_follows; })
  | SSH_MSG_NEWKEYS -> ok Ssh_msg_newkeys
  | SSH_MSG_KEXDH_INIT -> decode_mpint buf >>= fun (e, buf) ->
    ok (Ssh_msg_kexdh_init e)
  | SSH_MSG_KEXDH_REPLY ->
    decode_cstring buf >>= fun (k_s, buf) ->
    decode_mpint buf >>= fun (f, buf) ->
    decode_cstring buf >>= fun (hsig, buf) ->
    ok (Ssh_msg_kexdh_reply (k_s, f, hsig))
  | SSH_MSG_USERAUTH_REQUEST -> unimplemented ()
  | SSH_MSG_USERAUTH_FAILURE ->
    decode_nl buf >>= fun (nl, buf) ->
    decode_bool buf >>= fun (psucc, buf) ->
    ok (Ssh_msg_userauth_failure (nl, psucc))
  | SSH_MSG_USERAUTH_SUCCESS -> unimplemented ()
  | SSH_MSG_USERAUTH_BANNER ->
    decode_string buf >>= fun (s1, buf) ->
    decode_string buf >>= fun (s2, buf) ->
    ok (Ssh_msg_userauth_banner (s1, s2))
  | SSH_MSG_GLOBAL_REQUEST -> unimplemented ()
  | SSH_MSG_REQUEST_SUCCESS -> unimplemented ()
  | SSH_MSG_REQUEST_FAILURE -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_CONFIRMATION -> unimplemented ()
  | SSH_MSG_CHANNEL_OPEN_FAILURE -> unimplemented ()
  | SSH_MSG_CHANNEL_WINDOW_ADJUST -> unimplemented ()
  | SSH_MSG_CHANNEL_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EXTENDED_DATA -> unimplemented ()
  | SSH_MSG_CHANNEL_EOF -> unimplemented ()
  | SSH_MSG_CHANNEL_CLOSE -> unimplemented ()
  | SSH_MSG_CHANNEL_REQUEST -> unimplemented ()
  | SSH_MSG_CHANNEL_SUCCESS -> unimplemented ()
  | SSH_MSG_CHANNEL_FAILURE -> unimplemented ()

let scan_message buf =
  scan_pkt buf >>= function
  | None -> ok None
  | Some (pkt, clen) -> message_of_buf pkt >>= fun msg -> ok (Some msg)

(*
 * All below should be moved somewhere
 *)

let dh_gen_keys g peer_pub =
  let secret, my_pub = Nocrypto.Dh.gen_key g in
  guard_some
    (Nocrypto.Dh.shared g secret peer_pub)
    "Can't compute shared secret"
  >>= fun shared ->
  (* secret is y, my_pub is f or e, shared is k *)
  ok (secret, my_pub, shared)

let dh_server_compute_hash ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k =
  encode_cstring v_c >>= fun v_c ->
  encode_cstring v_s >>= fun v_s ->
  encode_cstring i_c >>= fun i_c ->
  encode_cstring i_s >>= fun i_s ->
  let e = encode_mpint e in
  let f = encode_mpint f in
  ok (Nocrypto.Hash.SHA1.digestv [ v_c; v_s; i_c; i_s; k_s; e; f; k ])

(* Only server obviously *)
let handle_kexdh_init e g rsa_secret =
  let v_c = Cstruct.create 0 in (* XXX *)
  let v_s = v_c in              (* XXX *)
  let i_c = v_c in              (* XXX *)
  let i_s = v_c in              (* XXX *)
  let rsa_pub = Nocrypto.Rsa.pub_of_priv rsa_secret in
  dh_gen_keys g e
  >>= fun (y, f, k) ->
  let k_s = encode_rsa rsa_pub in
  dh_server_compute_hash ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k
  >>= fun h ->
  let signature = Nocrypto.Rsa.PKCS1.sig_encode rsa_secret h in
  ok ()
  (* ok (Ssh_msg_kexdh_reply k_s f signature) *)

