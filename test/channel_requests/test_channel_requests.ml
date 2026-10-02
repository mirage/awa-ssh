open Awa

let now = Mtime_clock.now ()

(* OpenSSH sends keepalive@openssh.com as a channel request whenever a channel
   is open, and a name we do not recognise must still parse rather than error. *)
let channel_request_parsing () =
  let request name want_reply =
    let b = Buffer.create 32 in
    Wire.put_message_id b Ssh.MSG_CHANNEL_REQUEST;
    Wire.put_uint32 b 0;
    Wire.put_string b name;
    Wire.put_bool b want_reply;
    Result.get_ok (Wire.get_message (Buffer.contents b))
  in
  assert (request "keepalive@openssh.com" true =
          Ssh.Msg_channel_request (0, true, Ssh.Keepalive));
  assert (request "madeup@nonexistent.com" false =
          Ssh.Msg_channel_request
            (0, false, Ssh.Unknown ("madeup@nonexistent.com", "")))

(* RFC 4254 5.4: the reply names the channel by the peer's number for it, not
   ours.  And once we have sent a close we stop answering on that channel. *)
let channel_request_replies () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let c, channels =
    Result.get_ok (Channel.add ~id:7 ~win:4096 ~max_pkt:4096 Channel.empty_db)
  in
  let t = Server.{ t with channels; expect = None } in
  let request = Ssh.Msg_channel_request (Channel.id c, true, Ssh.Keepalive) in
  assert (Channel.their_id c = 7 && Channel.id c = 0);
  let _, replies, _ = Result.get_ok (Server.input_msg t request now) in
  assert (replies = [ Ssh.Msg_channel_failure (Channel.their_id c) ]);
  let closed = Channel.{ c with state = Sent_close } in
  let sent_close = Server.{ t with channels = Channel.update closed t.channels } in
  let _, replies, _ = Result.get_ok (Server.input_msg sent_close request now) in
  assert (replies = [])

(* The server disconnects on a request naming a channel it does not have. *)
let server_unknown_channel () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let t = Server.{ t with expect = None } in
  let request = Ssh.Msg_channel_request (0, true, Ssh.Keepalive) in
  match Result.get_ok (Server.input_msg t request now) with
  | _, [ Ssh.Msg_disconnect _ ], Some (Server.Disconnected _) -> ()
  | _ -> failwith "expected a disconnect for a request on an unknown channel"

let direct_tcpip_open () =
  let b = Buffer.create 64 in
  Wire.put_message_id b Ssh.MSG_CHANNEL_OPEN;
  Wire.put_string b "direct-tcpip";
  Wire.put_uint32 b 3;
  Wire.put_uint32 b 4096;
  Wire.put_uint32 b 1024;
  Wire.put_string b "example.com";
  Wire.put_uint32 b 80;
  Wire.put_string b "127.0.0.1";
  Wire.put_uint32 b 54321;
  assert (Result.get_ok (Wire.get_message (Buffer.contents b)) =
          Ssh.Msg_channel_open
            (3, 4096, 1024,
             Ssh.Direct_tcpip ("example.com", 80, "127.0.0.1", 54321)))

(* The client refuses a request naming a channel it does not have, exactly as the
   server does.  Client.t is abstract and Client.input_msg is not exported, so
   the only way in is Client.incoming -- which means driving the client all the
   way to Established against a real server. *)

let ( let* ) = Result.bind

(* Feed [buf] to the server, answering userauth, and return the bytes it emits. *)
let rec server_drain server buf out =
  match Server.pop_msg2 server buf with
  | Ok (server, None, buf) -> Ok (server, buf, out)
  | Ok (server, Some msg, buf) ->
    let* server, replies, event = Server.input_msg server msg now in
    let* server, replies =
      match event with
      | Some (Server.Userauth (_, userauth)) ->
        let* server, reply = Server.accept_userauth server userauth () in
        Ok (server, replies @ [ reply ])
      | _ -> Ok (server, replies)
    in
    let* server, bytes =
      List.fold_left (fun acc m ->
          let* server, sofar = acc in
          let* server, b = Server.output_msg server m in
          Ok (server, sofar ^ b))
        (Ok (server, "")) replies
    in
    server_drain server buf (out ^ bytes)
  | Error e -> Error e

let established_client () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let server, greeting = Server.make (Hostkey.Ed25519_priv priv) in
  let* server, to_client =
    List.fold_left (fun acc m ->
        let* server, sofar = acc in
        let* server, b = Server.output_msg server m in
        Ok (server, sofar ^ b))
      (Ok (server, "")) greeting
  in
  let client, first = Client.make ~user:"u" (`Password "pw") in
  (* Pump until the client says it is established. *)
  let rec pump client server to_client to_server n =
    if n = 0 then Error "client never reached Established" else
      let* server, to_server, more = server_drain server to_server "" in
      let to_client = to_client ^ more in
      let* client, out, events = Client.incoming client now to_client in
      let to_server = to_server ^ String.concat "" out in
      if List.exists (function `Established _ -> true | _ -> false) events then
        Ok (client, server)
      else
        pump client server "" to_server (pred n)
  in
  pump client server to_client (String.concat "" first) 20

let client_unknown_channel () =
  Result.get_ok
    (let* client, server = established_client () in
     (* A request for a channel number the client never had. *)
     let bogus = Ssh.Msg_channel_request (999, true, Ssh.Keepalive) in
     let* server, bytes = Server.output_msg server bogus in
     let* _client, replies, events = Client.incoming client now bytes in
     assert (events = [ `Disconnected ]);
     (* and what it sent back really is a disconnect: let the server parse it *)
     let* _server, msg, _ = Server.pop_msg2 server (String.concat "" replies) in
     (match msg with
      | Some (Ssh.Msg_disconnect (Ssh.DISCONNECT_PROTOCOL_ERROR, _, _)) -> ()
      | _ -> failwith "expected the client to send a protocol error disconnect");
     Ok ())

let () =
  Mirage_crypto_rng_unix.use_default ();
  channel_request_parsing ();
  channel_request_replies ();
  server_unknown_channel ();
  client_unknown_channel ();
  direct_tcpip_open ()
