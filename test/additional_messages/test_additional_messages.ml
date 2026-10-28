open Awa

let ( let* ) = Result.bind

let now = Mtime_clock.now ()

let fresh_server () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  Server.make (Hostkey.Ed25519_priv priv)

(* RFC 4253 11: ignore, debug and unimplemented may arrive at any time, so they
   must not depend on what we are waiting for. *)
let accepted_at_any_time () =
  let t, _ = fresh_server () in
  assert (t.Server.expect = Some Ssh.MSG_VERSION);
  let quietly_accepted msg =
    match Server.input_msg t msg now with
    | Ok (t', replies, event) ->
      assert (replies = []);
      assert (event = None);
      (* None of them should fundamentally change our state. *)
      assert (t'.Server.expect = t.Server.expect)
    | Error e ->
      failwith ("expected " ^ Fmt.to_to_string Ssh.pp_message msg
                ^ " to be accepted, got " ^ e)
  in
  quietly_accepted (Ssh.Msg_ignore "pretend echo");
  quietly_accepted (Ssh.Msg_debug (true, "displayed", "en"));
  quietly_accepted (Ssh.Msg_debug (false, "not displayed", ""));
  quietly_accepted (Ssh.Msg_unimplemented 42);

  (* A message that really is out of turn is still refused. *)
  assert (Result.is_error (Server.input_msg t Ssh.Msg_newkeys now))

(* An OpenSSH client ending their session normally should produce a
   Disconnected event. *)
let server_peer_disconnect () =
  let t, _ = fresh_server () in
  match
    Server.input_msg t
      (Ssh.Msg_disconnect (Ssh.DISCONNECT_BY_APPLICATION, "bye", "")) now
  with
  | Ok (_, [], Some (Server.Disconnected "bye")) -> ()
  | _ -> failwith "expected the peer's disconnect to yield a Disconnected event"

(* The peer's reason for disconnecting is the only account we get of why the
   connection ended, so it has to reach the caller and not just the log.  Both
   ends are still unkeyed right after the version exchange, so the message can
   be handed to the client as a plaintext packet without a full handshake. *)
let client_peer_disconnect () =
  Result.get_ok
    (let server, greeting = fresh_server () in
     let version = List.find (function Ssh.Msg_version _ -> true | _ -> false) greeting in
     let* server, version = Server.output_msg server version in
     let* _server, bye =
       Server.output_msg server
         (Ssh.Msg_disconnect (Ssh.DISCONNECT_BY_APPLICATION, "bye", ""))
     in
     let client, _ = Client.make `No_authentication ~user:"u" (`Password "pw") in
     match Client.incoming client now (version ^ bye) with
     | Error e ->
       assert (e = {|disconnected by peer: Disconnected by application "bye"|});
       Ok ()
     | Ok (_, _, events) ->
       failwith (Fmt.str "expected the peer's disconnect to be an error, got %a"
                   Fmt.(list ~sep:(any ", ") Client.pp_event) events))

let () =
  Mirage_crypto_rng_unix.use_default ();
  accepted_at_any_time ();
  server_peer_disconnect ();
  client_peer_disconnect ()
