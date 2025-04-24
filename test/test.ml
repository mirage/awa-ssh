(*
 * Copyright (c) 2016 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

let () = Printexc.record_backtrace true

open Awa
open Printf
open Util

let now = Mtime_clock.now ()

let tty_out = Unix.isatty Unix.stdout && Unix.getenv "TERM" <> "dumb"
let colored_or_not cfmt fmt =
  if tty_out then sprintf cfmt else sprintf fmt
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let test_ok = Ok ()

let trap_exn f =
  try (f ()) with exn ->
    Error (sprintf "Caught exception: %s\n%s\n%!"
             (Printexc.to_string exn)
             (Printexc.get_backtrace ()))

let cipher_key_of cipher key iv =
  let open Mirage_crypto in
  let open Cipher in
  match cipher with
  | Plaintext -> { cipher = Plaintext;
                   cipher_key = Plaintext_key }
  | Aes128_ctr | Aes192_ctr | Aes256_ctr ->
    let iv = AES.CTR.ctr_of_octets iv in
    { cipher;
      cipher_key = Aes_ctr_key ((AES.CTR.of_secret key), iv) }
  | Aes128_cbc | Aes192_cbc | Aes256_cbc ->
    { cipher;
      cipher_key = Aes_cbc_key ((AES.CBC.of_secret key), iv) }
  | Chacha20_poly1305 ->
    let key = Chacha20.of_secret key in
    { cipher; cipher_key = Chacha20_poly1305_key (key, key) }

let hmac_key_of hmac key = Hmac.{ hmac; key }

let encrypt_plain msg =
  fst (Packet.encrypt (Kex.make_plaintext ()) msg)

let decrypt_plain buf =
  match Packet.decrypt (Kex.make_plaintext ()) buf with
  | Ok (Some (pkt, buf, _)) -> Ok (Some (pkt, buf))
  | Ok None -> Ok None
  | Error e -> Error e

(* let assert_ok x = assert (is_ok x) *)

let assert_error x = assert (Result.is_error x)

let assert_none = function None -> () | _ -> failwith "Expected None"

let assert_false x = assert (not x)

let get_some = function None -> failwith "Expected Some" | Some x -> x

let timeout s =
  let left = Unix.alarm s in
  if s <> 0 && left <> 0 then
    failwith "Timeout already pending"

let t_banner () =
  let good_strings = [
    "SSH-2.0-foobar lalal\r\n";
    "\r\n\r\nSSH-2.0-foobar lalal\r\n";
    "SSH-2.0-foobar lalal lololo\r\n";
    "SSH-2.0-OpenSSH_6.9\r\n";
    "SSH-2.0-Open-SSH_6.9\r\n";
    "SSH-2.0-babeld-72deb3a2\r\n";
    "Some crap before\r\nSSH-2.0-OpenSSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-Open-SSH_6.9\r\n";
    "\r\nSSH-2.0-Open-SSH_6.9\r\nSom crap after";
    "SSH-2.0-OpenSSH_6.9\r\nSomeCrap After\r\n";
    "SSH-2.0-OpenSSH_7.4p1 Debian-6-lala-lolo\r\n";
  ]
  in
  List.iter (fun s ->
      match Wire.get_version (Cstruct.of_string s) with
      | Ok (Some _, _) -> ()
      | Ok (None, _) -> failwith "expected some"
      | Error e -> failwith e)
    good_strings;

  let bad_strings = [
    "SSH-2.0\r\n";
    "SSH-1.0-foobar lalal lololo\r\n";
    "SSH-2.0-partiallineomg";
  ]
  in
  List.iter (fun s ->
      match Wire.get_version (Cstruct.of_string s) with
      | Ok (Some _, _) -> failwith ("expected none or error: " ^ s)
      | Ok (None, _) -> ()
      | Error _ -> ())
    bad_strings;
  test_ok

let t_parsing () =
  let open Ssh in
  (*
   * Case 1: Full buff consumed
   *)
  let msg = Msg_ignore "a" in
  let buf = encrypt_plain msg in
  let* r = decrypt_plain buf in
  let* pkt, rbuf = guard_some r "decrypt gave no packet" in
  let* msg2 = Packet.to_msg pkt in
  let* () = guard (msg = msg2) "decrypted msg differs from encrypted" in
  let* () = guard (Cstruct.length rbuf = 0) "buffer is not fully parsed" in
  (*
   * Case 2: 1 byte left
   *)
  let msg = Msg_ignore "a" in
  let buf, _ = Packet.encrypt (Kex.make_plaintext ()) msg in
  let buf = Cstruct.append buf (Cstruct.of_string "b") in
  let pkt, rbuf = get_some @@ Result.get_ok @@ decrypt_plain buf in
  let msg2 = Result.get_ok @@ Packet.to_msg pkt in
  assert (msg = msg2);
  assert (Cstruct.length rbuf = 1);

  (* Case 3: Test a zero pkt_len *)
  let buf = Bytes.create 64 in
  Packet.set_pkt_len buf 0;
  Packet.set_pad_len buf 0;
  let e = Result.get_error (decrypt_plain (Cstruct.of_bytes buf)) in
  assert (e = "decrypt: Bogus pkt len");

  let id msg =
    let buf = encrypt_plain msg in
    let pkt, buf = get_some @@ Result.get_ok @@ decrypt_plain buf in
    let msg2 = Result.get_ok @@ Packet.to_msg pkt in
    assert (Cstruct.length buf = 0);
    match msg, msg2 with
    (* Can't compare Cstruct.t, must unpack and Cstruct.equal () *)
    | Msg_userauth_request (user_a, service_a, authmethod_a),
      Msg_userauth_request (user_b, service_b, authmethod_b) ->
      assert ((user_a, service_a) = (user_b, service_b));
      assert (auth_method_equal authmethod_a authmethod_b);
    | Msg_kex (ida, dataa), Msg_kex (idb, datab) ->
      assert (ida = idb && Cstruct.equal dataa datab)
    | Msg_channel_open_confirmation (a1, a2, a3, a4, a5),
      Msg_channel_open_confirmation (b1, b2, b3, b4, b5) ->
      assert (a1 = b1);
      assert (a2 = b2);
      assert (a3 = b3);
      assert (a4 = b4);
      assert (Cstruct.equal a5 b5);
    | Msg_channel_request (a1, a2, Raw_data a3),
      Msg_channel_request (b1, b2, Raw_data b3) ->
      assert (a1 = b1);
      assert (a2 = b2);
      assert (Cstruct.equal a3 b3);
    | Msg_channel_data (a1, a2),
      Msg_channel_data (b1, b2) ->
      assert (a1 = b1);
      assert (Cstruct.equal a2 b2);
    | Msg_channel_extended_data (a1, a2, a3),
      Msg_channel_extended_data (b1, b2, b3) ->
      assert (a1 = b1);
      assert (a2 = b2);
      assert (Cstruct.equal a3 b3);
    | msg, msg2 -> assert (msg = msg2)
  in
  let long = Int32.of_int 180586 in
  (* let mpint = Z.of_int 180586 in *)
  let cstring = "The Conquest of Bread" in
  (* XXX slow *)
  let rsa = Mirage_crypto_pk.Rsa.(generate ~bits:2048 ()) in
  let priv_rsa = Hostkey.Rsa_priv rsa in
  let pub_rsa = Hostkey.Rsa_pub (Mirage_crypto_pk.Rsa.pub_of_priv rsa) in
  let pub_rsa_raw = Wire.blob_of_pubkey pub_rsa in
  let alg = Hostkey.Rsa_sha1 in
  let alg_raw = Hostkey.alg_to_string alg in
  let signature = Hostkey.sign alg priv_rsa cstring in
  let l =
    [ Msg_disconnect (DISCONNECT_PROTOCOL_ERROR, "foo", "bar");
      Msg_ignore "Fora Temer";
      Msg_unimplemented long;
      Msg_debug (false, "Fora", "Temer");
      Msg_service_request "Fora Temer";
      Msg_service_accept "Ricardo Flores Magon";
      (* Msg_kexinit foo; *)
      (* Msg_kexdh_init mpint; *) (* two-step parsing *)
      (* Msg_kexdh_reply (pub_rsa, mpint, signature); *) (* two-step parsing *)
      Msg_newkeys;
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Pubkey (alg_raw, pub_rsa_raw, None));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Pubkey (alg_raw, pub_rsa_raw, Some (alg_raw, signature)));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Password ("a", Some "b"));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Password ("a", None));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth", Authnone);
      Msg_userauth_failure (["Fora"; "Temer"], true);
      Msg_userauth_success;
      Msg_userauth_banner ("Fora", "Temer");
      (* Msg_userauth_pk_ok pub_rsa; *)
      Msg_global_request
        ("tcpip-forward", true,
        Tcpip_forward ("127.0.0.1", long));
      Msg_request_success (None);
      Msg_request_failure;
      Msg_channel_open
        (long, long, long,
         X11 ("::1", long));
      Msg_channel_open_confirmation
        (long, long, long, long, Cstruct.of_string "Freedom of Mind");
      Msg_channel_open_failure
        (long, long, "Because you stink", "enEN");
      Msg_channel_window_adjust (long, Int32.succ long);
      Msg_channel_data (long, Cstruct.of_string "DATADATA");
      Msg_channel_extended_data (long, long, Cstruct.of_string "DATADATA");
      Msg_channel_eof long;
      Msg_channel_close long;
      Msg_channel_request (long, false, Pty_req ("a", long, long, long, long, "b"));
      Msg_channel_request (long, false, X11_req (false, "a", "b", long));
      Msg_channel_request (long, false, Env ("a", "b"));
      Msg_channel_request (long, false, Shell);
      Msg_channel_request (long, false, Exec "a");
      Msg_channel_request (long, false, Subsystem "a");
      Msg_channel_request (long, false, Window_change (long, long, long, long));
      Msg_channel_request (long, false, Xon_xoff false);
      Msg_channel_request (long, false, Signal "a");
      Msg_channel_request (long, false, Exit_status long);
      Msg_channel_request (long, false, Exit_signal ("a", false, "b", "c"));
      (* It's illegal to serialize Raw_data for now *)
      (* Msg_channel_request (long, false, Raw_data (Cstruct.of_string "Hegel")); *)
      Msg_channel_success long;
      Msg_channel_failure long; ]
  in
  List.iter (fun m -> id m) l;
  test_ok

let t_key_exchange () =
  (* Read a pcap file and see if it makes sense. *)
  let file = "data/kex.packet" in
  let fd = Unix.(openfile file [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  let pkt, _ = get_some @@ Result.get_ok @@ decrypt_plain buf in
  let msg = Result.get_ok @@ Packet.to_msg pkt in
  let () = match msg with
    | Ssh.Msg_kexinit _ -> ()
    | _ -> failwith "Expected Msg_kexinit"
  in
  Unix.close fd;
  test_ok

let t_namelist () =
  let s = ["The";"Conquest";"Of";"Bread"] in
  let buf = Dbuf.to_cstruct @@ Wire.put_nl s (Dbuf.create ()) in
  assert (Cstruct.length buf = 4 + String.length (String.concat "," s));
  assert (s = fst (Result.get_ok (Wire.get_nl buf)));
  test_ok

let t_mpint () =
  let assert_byte buf off v =
    assert ((String.get_uint8 buf off) = v)
  in

  (*
   * Case 1: Make sure zeroes are stripped from the beggining.
   *)
  let head = Cstruct.create 4 in
  let data = Cstruct.create 4 in
  Cstruct.set_uint8 data 0 0x00;
  Cstruct.set_uint8 data 1 0x00;
  Cstruct.set_uint8 data 2 0xff;
  Cstruct.set_uint8 data 3 0x02;
  Cstruct.BE.set_uint32 head 0 (Int32.of_int (Cstruct.length data));
  let mpint = fst @@ Result.get_ok @@ Wire.get_mpint (Cstruct.append head data) in
  let buf = Mirage_crypto_pk.Z_extra.to_octets_be mpint in
  assert (String.length buf = 2); (* Cuts the first two zeros *)
  assert_byte buf 0 0xff;
  assert_byte buf 1 0x02;

  (*
   * Case 2: Test identity
   *)
  assert (mpint =
          (fst @@ Result.get_ok
             (Wire.get_mpint
                (Dbuf.to_cstruct @@
                      Wire.put_mpint mpint (Dbuf.create ())))));

  (*
   * Case 3: Test the other way from 1, one zero must be prepended
   * since the first byte is negative (0xff).
   *)
  let buf = Dbuf.to_cstruct @@ Wire.put_mpint mpint (Dbuf.create ()) in
  (* 4 for header + 1 zero prepended + 2 data*)
  assert (Cstruct.length buf = 4 + 1 + 2);
  let buf' = Cstruct.to_string buf in
  assert_byte buf' 0 0x00;
  assert_byte buf' 1 0x00;
  assert_byte buf' 2 0x00;
  assert_byte buf' 3 0x03;
  assert_byte buf' 4 0x00;
  assert_byte buf' 5 0xff;
  assert_byte buf' 6 0x02;

  (*
   * Case 4: Make sure negative are errors.
   *)
  Cstruct.set_uint8 buf 4 0x80;
  let e = Result.get_error (Wire.get_mpint buf) in
  assert (e = "Negative mpint");
  test_ok

let t_version () =
  let t, _ = Server.make (Hostkey.Rsa_priv (Mirage_crypto_pk.Rsa.generate ~bits:2048 ())) in
  let client_version = "SSH-2.0-OpenSSH_6.9\r\n" in
  let* t, msg, input_buffer =
    Server.pop_msg2 t (Cstruct.of_string client_version)
  in
  match get_some msg with
  | Ssh.Msg_version v ->
    assert (Cstruct.length input_buffer = 0);
    assert (v = "SSH-2.0-OpenSSH_6.9");
    let t, _, _ = Result.get_ok (Server.input_msg t (Ssh.Msg_version v) now) in
    assert (t.Server.client_version = (Some "SSH-2.0-OpenSSH_6.9"));
    test_ok
  | _ -> Error "Expected Ssh_version"

let t_crypto () =
  let test keys =
    let txt = "abcdefghijklmnopqrstuvxz" in
    let msg = Ssh.Msg_ignore txt in
    let buf_enc, _ = Packet.encrypt keys msg in
    let pkt, buf, _ =
      get_some @@ Result.get_ok @@ Packet.decrypt keys buf_enc
    in
    let msg = Result.get_ok @@ Packet.to_msg pkt in
    let () = match msg with
      | Ssh.Msg_ignore s ->
        assert (s = txt)
      | _ -> failwith "bad msg"
    in
    assert (Cstruct.length buf = 0)
    (* Side effect below ! *)
    (* Nocrypto.Cipher_block.Counter.add16 keys.Kex.iv 0 Int64.(succ one); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next.Kex.iv); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next2.Kex.iv) *)
  in
  let make cipher hmac =
    let secret = "Pyotr Alexeyevich Kropotkin 1842" in
    let iv = String.sub secret 0 16 in
    let cipher = cipher_key_of cipher secret iv in
    let mac = hmac_key_of hmac secret in
    Kex.{ cipher; mac; seq = Int32.zero; tx_rx = Int64.zero }
  in
  List.iter (fun cipher ->
      List.iter (fun hmac ->
          test (make cipher hmac))
        Hmac.preferred)
    Cipher.preferred;
  test_ok

let t_openssh_pub () =
  let fd = Unix.(openfile "data/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = Result.get_ok (Wire.pubkey_of_openssh file_buf) in
  let buf = Wire.openssh_of_pubkey key in
  assert (Cstruct.equal file_buf buf);
  Unix.close fd;
  test_ok

let t_signature () =
  let priv = Hostkey.Rsa_priv (Mirage_crypto_pk.Rsa.generate ~bits:2048 ()) in
  let pub = Hostkey.pub_of_priv priv in
  let unsigned = Mirage_crypto_rng.generate 128 in
  let alg = Hostkey.Rsa_sha1 in
  let signed = Hostkey.sign alg priv unsigned in
  assert (Hostkey.verify alg pub ~signed ~unsigned);
  (* Corrupt every one byte in the signature, all should fail *)
  let s = Bytes.of_string signed in
  for off = 0 to pred (Bytes.length s) do
    let evilbyte = Bytes.get_uint8 s off in
    Bytes.set_uint8 s off (succ evilbyte);
    assert_false (Hostkey.verify alg pub ~signed:(Bytes.unsafe_to_string s) ~unsigned);
    Bytes.set_uint8 s off evilbyte;
  done;
  test_ok

let t_ignore_next_packet () =
  let t, _ = Server.make (Hostkey.Rsa_priv (Mirage_crypto_pk.Rsa.generate ~bits:2048 ())) in
  let t = Server.{ t with client_version = Some "SSH-2.0-client";
                          expect = Some(Ssh.MSG_KEXINIT) }
  in
  let kexinit = Ssh.{ (Kex.make_kexinit Hostkey.preferred_algs Kex.supported ()) with
                      encryption_algs_ctos = ["aes256-cbc"];
                      first_kex_packet_follows = true }
  in
  (* Should set ignore_next_packet since the guess of the client is wrong *)
  let message = Ssh.Msg_kexinit kexinit in
  let buf = encrypt_plain message in
  let t, message, _ = Result.get_ok (Server.pop_msg2 t buf) in
  let message = get_some message in
  let t, _, _ = Result.get_ok (Server.input_msg t message now) in
  assert (t.Server.ignore_next_packet = true);
  (* Should ignore the next packet since ignore_next_packet is true *)
  let message = Ssh.Msg_debug(true, "woop", "Look at me") in
  let buf = encrypt_plain message in
  let t, msg, _ = Result.get_ok (Server.pop_msg2 t buf) in
  assert (t.Server.ignore_next_packet = false);
  assert (msg = None);
  (* Should not ignore the packet which follows after *)
  let buf = encrypt_plain message in
  let t, msg, _ = Result.get_ok (Server.pop_msg2 t buf) in
  assert (t.Server.ignore_next_packet = false);
  assert (msg = Some message);
  test_ok

let t_channel_input () =
  let x = Channel.make_end Int32.zero Ssh.channel_win_len Ssh.channel_max_pkt_len in
  let c = Channel.make ~us:x ~them:x in
  let d =
    Mirage_crypto_rng.generate
      Int32.(add Ssh.channel_win_len Int32.one |> Int32.to_int) |> Cstruct.of_string
  in
  (* Case 1: No adjustments, just window consumption *)
  let d' = Cstruct.sub d 0 32 in
  let* c', dn', adj' = Channel.input_data c d' in
  assert (Cstruct.length d' = 32);
  assert (Cstruct.equal d' dn');
  assert (adj' = None);
  (* Make sure our window was drained by 32 bytes *)
  assert Channel.(c'.us.win = (Int32.sub c.them.win
                                 (Cstruct.length d' |> Int32.of_int)));
  (* Case 2, Input 2/3 of the window, adjustment must match full window  *)
  let len' = Cstruct.length d / 4 * 3 in
  let d' = Cstruct.sub d 0 len' in
  let* c', dn', adj' = Channel.input_data c d' in
  assert Channel.(c'.us.win = Ssh.channel_win_len);
  assert (Cstruct.length d' = len');
  assert (Cstruct.equal d' dn');
  let adj'' = Some (Ssh.Msg_channel_window_adjust
                      (Int32.zero, Int32.of_int len')) in
  assert (adj' = adj'');
  (* Case 3, Make sure we discard data above our window *)
  let* _c', dn', _adj' = Channel.input_data c d in
  assert (not (Cstruct.equal d dn'));
  assert (Cstruct.length d = Cstruct.length dn' + 1);
  test_ok

let t_channel_output () =
  let x = Channel.make_end Int32.zero Ssh.channel_win_len Ssh.channel_max_pkt_len in
  let c = Channel.make ~us:x ~them:x in
  let d =
    Mirage_crypto_rng.generate
      Int32.(add Ssh.channel_win_len Int32.one |> Int32.to_int) |> Cstruct.of_string
  in
  (* Case 1: Small output, single message *)
  let d' = Cstruct.sub d 0 32 in
  let* c', msgs' = Channel.output_data ~flush:false c d' in
  assert ((List.length msgs') = 1);
  let msg' = List.hd msgs' in
  let* () =
    match msg' with
    | Ssh.Msg_channel_data (id, buf) ->
      assert (id = Int32.zero);
      assert (Cstruct.equal buf d');
      Ok ()
    | _ -> Error "Unexpected msg'"
  in
  (* Add data len back, see if we have the full window available *)
  assert (Channel.(Int32.add c'.them.win (Int32.of_int (Cstruct.length d'))) =
          Ssh.channel_win_len);
  (* Case 2: Enough output for 2 messages, first is 64, second 32 *)
  (* Make sure we didn't change defaults *)
  assert ((Int32.to_int Channel.(c.them.max_pkt)) = (64 * 1024));
  let d' = Cstruct.sub d 0 (96 * 1024) in
  let* _c', msgs' = Channel.output_data ~flush:false c d' in
  assert ((List.length msgs') = 2);
  let msg1' = List.nth msgs' 0 in
  let msg2' = List.nth msgs' 1 in
  let* () =
    match msg1' with
    | Ssh.Msg_channel_data (id, buf) ->
      assert (id = Int32.zero);
      assert (Cstruct.equal buf (Cstruct.sub d 0 (64 * 1024)));
      Ok ()
    | _ -> Error "unexpected msg1'"
  in
  let* () =
    match msg2' with
    | Ssh.Msg_channel_data (id, buf) ->
      assert (id = Int32.zero);
      let d'' = Cstruct.shift d (64 * 1024) in
      let d'' = Cstruct.sub d'' 0 (32 * 1024) in
      assert (Cstruct.equal buf d'');
      Ok ()
    | _ -> Error "unexpected msg2'"
  in
  (* Case 3: See if peer window is respected, one byte will be outside the window *)
  let* c', msgs' = Channel.output_data ~flush:false c d in
  let exp_nmsgs' = 1 + Cstruct.length d / Int32.to_int Ssh.channel_max_pkt_len in
  (* printf "exp_nmsgs = %d (%d/%d) l=%d\n%!"
   *   exp_nmsgs'
   *   (Cstruct.len d)
   *   (Int32.to_int Ssh.channel_max_pkt_len)
   *   (List.length msgs'); *)
  assert (exp_nmsgs' = (List.length msgs'));
  let bufs' = List.map (function
      | Ssh.Msg_channel_data (_, buf) -> buf
      | _ -> invalid_arg "unexpected buf")
      msgs'
  in
  let rebuild' =
    List.fold_left (fun a buf -> Cstruct.append a buf)
      (Cstruct.create 0) bufs'
  in
  (* dwin is all of d that fit the window, one byte was out *)
  let dwin' = Cstruct.sub d 0 (Cstruct.length d - 1) in
  assert (Cstruct.equal rebuild' dwin');
  (* Now check if the byte outside of the window is there, and makes sense *)
  assert (Cstruct.length c'.Channel.tosend = 1);
  assert (Channel.(c'.them.win) = Int32.zero);
  let d'' = Cstruct.shift d (Cstruct.length d - 1) in
  assert (Cstruct.equal d'' Channel.(c'.tosend));
  (* Case 4: Widen the window, see if we get our byte back *)
  let* c'', msgs' = Channel.adjust_window c' (Int32.of_int 100) in
  assert ((List.length msgs') = 1);
  assert (Cstruct.length c''.Channel.tosend = 0);
  assert (Channel.(c''.them.win) = (Int32.of_int 99));
  test_ok

let t_openssh_client () =
  let s1 = "Georg Wilhelm Friedrich Hegel" in
  let s2 = "Karl Marx" in
  let ossh_cmd = "ssh -p 18022 awa@127.0.0.1 -i data/awa_test_rsa echo" in
  let awa_cmd = "./awa_test_server.exe" in
  let awa_args = Array.of_list [] in
  let null = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0o666 in
  ignore @@ Unix.system "pkill awa_test_server";
  let awa_pid = Unix.create_process awa_cmd awa_args null null null in
  Unix.sleepf 0.1;
  let ossh = Unix.open_process_full ossh_cmd (Unix.environment ()) in
  let ossh_out, ossh_in = match ossh with o, i, _e -> o, i in
  output_string ossh_in s1;
  output_char ossh_in '\n';
  flush ossh_in;
  assert (input_line ossh_out = s1);
  output_string ossh_in s2;
  output_char ossh_in '\n';
  flush ossh_in;
  assert (input_line ossh_out = s2);
  ignore @@ Unix.kill awa_pid Sys.sigterm;
  ignore @@ Unix.close_process_full ossh;
  ignore @@ Unix.close null;
  test_ok

let run_test test =
  let name = snd test in
  let run () =
    timeout 5;
    let r = trap_exn (fst test) in
    timeout 0;
    r
  in
  printf "%s %-40s%!" (blue "%s" "Test") (yellow "%s" name);
  match run () with
  | Ok _ -> printf "%s\n%!" (green "ok")
  | Error e -> printf "%s\n%s\n%!" (red "failed") e

let all_tests = [
  (t_parsing, "basic parsing");
  (t_banner, "version banner");
  (t_key_exchange, "key exchange");
  (t_namelist, "namelist conversions");
  (t_mpint, "mpint conversions");
  (t_version, "version exchange");
  (t_crypto, "encrypt/decrypt");
  (t_openssh_pub, "OpenSSH public key format");
  (t_signature, "signatures");
  (t_ignore_next_packet, "ignore next packet");
  (t_channel_input, "channel data input");
  (t_channel_output, "channel data output");
  (* disabled: requires network connectivity
     (t_openssh_client, "OpenSSH@awa_ssh echo server"); *)
]

let _ =
  Mirage_crypto_rng_unix.use_default ();
  Sys.set_signal Sys.sigalrm (Sys.Signal_handle (fun _ -> failwith "timeout"));
  Unix.chmod "data/awa_test_rsa" 0o600;
  List.iter run_test all_tests;
