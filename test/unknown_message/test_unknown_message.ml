open Awa

let now = Mtime_clock.now ()

let fresh_server () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  Server.{ t with client_version = Some "SSH-2.0-client";
                  expect = Some Ssh.MSG_KEXINIT }

(* A packet carrying a message id we do not know.  With plaintext keys the
   payload starts at offset 5, right after the length and the padding length. *)
let forged_packet id =
  let buf =
    Bytes.of_string
      (fst (Packet.encrypt (Kex.make_plaintext ())
              (Ssh.Msg_ignore "never looked at")))
  in
  Bytes.set_uint8 buf 5 id;
  Bytes.unsafe_to_string buf

(* RFC 4253 11.4: an unrecognised message must be answered with
   SSH_MSG_UNIMPLEMENTED carrying the sequence number of the packet that
   brought it, and otherwise ignored. *)
let unknown_message_answered () =
  assert (Ssh.int_to_message_id 200 = None);
  let t = fresh_server () in
  let t, msg, _ = Result.get_ok (Server.pop_msg2 t (forged_packet 200)) in
  (match Option.get msg with
   | Ssh.Msg_unknown 200 -> ()
   | m -> failwith ("expected an unknown message, got "
                    ^ Fmt.to_to_string Ssh.pp_message m));
  let t', replies, event =
    Result.get_ok (Server.input_msg t (Option.get msg) now)
  in
  (* It was the first packet we received, so sequence number zero. *)
  assert (replies = [ Ssh.Msg_unimplemented 0 ]);
  assert (event = None);
  (* And it did not disturb what we were waiting for. *)
  assert (t'.Server.expect = Some Ssh.MSG_KEXINIT);
  (* We never send one: it has no id to put on the wire. *)
  assert (match Wire.put_message (Buffer.create 16) (Ssh.Msg_unknown 200) with
          | exception Invalid_argument _ -> true
          | () -> false)

(* Sequence numbers are unsigned and wrap at 2^32.  Receiving the packet below
   takes the counter from 2^32 - 1 to 0, so the number we must name is
   2^32 - 1, not -1. *)
let sequence_number_wraps () =
  let t = fresh_server () in
  let t = Server.{ t with keys_ctos = { t.keys_ctos with Kex.seq = -1l } } in
  let t, msg, _ = Result.get_ok (Server.pop_msg2 t (forged_packet 200)) in
  assert (t.Server.keys_ctos.Kex.seq = 0l);
  let _, replies, _ = Result.get_ok (Server.input_msg t (Option.get msg) now) in
  assert (replies = [ Ssh.Msg_unimplemented 4294967295 ])

(* The number to name is the one from the direction the packet came in on, so
   the client takes it from the server-to-client keys and the server from the
   client-to-server ones.  The Msg_ignore below is what tells the two apart: it
   advances the receive counter without drawing a reply, leaving the client's
   two counters one number apart. *)
let client_names_the_receive_sequence () =
  let client, _ = Client.make `No_authentication ~user:"u" (`Password "pw") in
  let feed client buf =
    let client, out, _ = Result.get_ok (Client.incoming client now buf) in
    client, String.concat "" out
  in
  let client, _ = feed client "SSH-2.0-server\r\n" in
  let client, out =
    feed client (fst (Packet.encrypt (Kex.make_plaintext ())
                        (Ssh.Msg_ignore "never looked at")))
  in
  assert (out = "");
  let _, out = feed client (forged_packet 200) in
  let _, reply, _ = Result.get_ok (Server.pop_msg2 (fresh_server ()) out) in
  match Option.get reply with
  | Ssh.Msg_unimplemented 1 -> ()
  | m -> failwith ("expected unimplemented 1, got "
                   ^ Fmt.to_to_string Ssh.pp_message m)

let () =
  Mirage_crypto_rng_unix.use_default ();
  unknown_message_answered ();
  sequence_number_wraps ();
  client_names_the_receive_sequence ()
