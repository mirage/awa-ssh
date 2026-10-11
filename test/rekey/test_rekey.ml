open Awa

let ( let* ) = Result.bind

let now = Mtime_clock.now ()

(* Feed [buf] to the server and return the bytes it emits.  Userauth is answered
   unless [answer_auth] is false, which leaves the client keyed and waiting. *)
let rec server_drain ?(answer_auth = true) server buf out =
  match Server.pop_msg2 server buf with
  | Ok (server, None, buf) -> Ok (server, buf, out)
  | Ok (server, Some msg, buf) ->
    let* server, replies, event = Server.input_msg server msg now in
    let* server, replies =
      match event with
      | Some (Server.Userauth (_, userauth)) when answer_auth ->
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
    server_drain ~answer_auth server buf (out ^ bytes)
  | Error e -> Error e

let serialise server msgs =
  List.fold_left (fun acc m ->
      let* server, sofar = acc in
      let* server, b = Server.output_msg server m in
      Ok (server, sofar ^ b))
    (Ok (server, "")) msgs

(* Returns the client, the server, and the channel number the client answers to. *)
let established_client () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let server, greeting = Server.make (Hostkey.Ed25519_priv priv) in
  let* server, to_client = serialise server greeting in
  let client, first = Client.make `No_authentication ~user:"u" (`Password "pw") in
  let rec pump client server to_client to_server n =
    if n = 0 then Error "client never reached Established" else
      let* server, to_server, more = server_drain server to_server "" in
      let to_client = to_client ^ more in
      let* client, out, events = Client.incoming client now to_client in
      let to_server = to_server ^ String.concat "" out in
      match List.find_map (function `Established id -> Some id | _ -> None) events with
      | Some id -> Ok (client, server, id, to_server)
      | None -> pump client server "" to_server (pred n)
  in
  pump client server to_client (String.concat "" first) 20

(* Run whatever is in flight to a standstill, collecting the client's events. *)
let rec settle client server to_client to_server events n =
  if n = 0 then Ok (client, server, events) else
    let* server, to_server, more = server_drain server to_server "" in
    let to_client = to_client ^ more in
    let* client, out, evs = Client.incoming client now to_client in
    let to_server = to_server ^ String.concat "" out in
    if to_server = "" && more = "" then Ok (client, server, events @ evs)
    else settle client server "" to_server (events @ evs) (pred n)

(* An OpenSSH server rekeys after 1 to 4 GB, so a client that cannot answer a
   KEXINIT while established is a client that dies on any long transfer.  The
   proof that it worked is not that nothing errored, but that data still flows
   in both directions afterwards: that only holds if both ends rotated to the
   same new keys. *)
let established_session_survives_a_rekey () =
  Result.get_ok
    (let* client, server, id, to_server = established_client () in
     let* client, server, _ = settle client server "" to_server [] 20 in
     (* the server asks for a new key exchange *)
     let server, kexinit =
       match Server.rekey server with
       | Some (server, msg) -> server, msg
       | None -> failwith "server would not rekey"
     in
     let* server, bytes = serialise server [ kexinit ] in
     let* client, server, events = settle client server bytes "" [] 20 in
     assert (events = []);
     (* client -> server still decrypts under the new keys *)
     let* client, out = Client.outgoing_data client "ping" in
     let* server, _, more = server_drain server (String.concat "" out) "" in
     ignore more;
     (* and server -> client *)
     let* server, msgs = Server.output_channel_data server id "pong" in
     let* server, bytes = serialise server msgs in
     let* _client, _, events = Client.incoming client now bytes in
     ignore server;
     assert (List.exists (function `Channel_data (_, "pong") -> true | _ -> false) events);
     Ok ())

(* RFC 4253 9 permits a rekey at any time after the first NEWKEYS, but
   authentication cannot be suspended and resumed, so a KEXINIT arriving
   before the session is established fails the connection, as it does for
   OpenSSH's client. *)
let kexinit_before_established_is_refused () =
  Result.get_ok
    (let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
     let server, greeting = Server.make (Hostkey.Ed25519_priv priv) in
     let* server, to_client = serialise server greeting in
     let client, first =
       Client.make `No_authentication ~user:"u" (`Password "pw")
     in
     (* Run to a standstill with the userauth request left unanswered. *)
     let rec pump client server to_client to_server n =
       if n = 0 then Error "client never asked to authenticate" else
         let* server, to_server, more =
           server_drain ~answer_auth:false server to_server ""
         in
         let to_client = to_client ^ more in
         let* client, out, _ = Client.incoming client now to_client in
         let to_server = to_server ^ String.concat "" out in
         if to_server = "" && more = "" then Ok (client, server)
         else pump client server "" to_server (pred n)
     in
     let* client, server = pump client server to_client (String.concat "" first) 20 in
     (match server.Server.auth_state with
      | Server.Inprogress _ -> ()
      | Server.Preauth | Server.Done _ ->
        failwith "expected authentication to be in progress");
     (* the server asks for a rekey regardless *)
     let server, kexinit =
       match Server.rekey server with
       | Some (server, msg) -> server, msg
       | None -> failwith "server would not rekey"
     in
     let* server, bytes = serialise server [ kexinit ] in
     ignore server;
     match Client.incoming client now bytes with
     | Ok _ -> failwith "a KEXINIT during authentication was accepted"
     | Error msg ->
       assert (msg = "received rekeying attempt before the session is established");
       Ok ())

(* A second KEXINIT before NEWKEYS is a protocol error, not a rekey request:
   RFC 4253 7.1 allows one per exchange, and OpenSSH likewise disconnects with
   "multiple KEXINIT received from peer". *)
let second_kexinit_during_an_exchange_is_refused () =
  Result.get_ok
    (let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
     let server, greeting = Server.make (Hostkey.Ed25519_priv priv) in
     let* server, to_client = serialise server greeting in
     let client, _ =
       Client.make `No_authentication ~user:"u" (`Password "pw")
     in
     (* the banner and the server's KEXINIT put the client mid-exchange *)
     let* client, _, _ = Client.incoming client now to_client in
     let* server, again =
       serialise server [ Ssh.Msg_kexinit server.Server.server_kexinit ]
     in
     ignore server;
     match Client.incoming client now again with
     | Ok _ -> failwith "a second KEXINIT was accepted"
     | Error msg ->
       assert (msg = "received a second KEXINIT during a key exchange");
       Ok ())

let () =
  Mirage_crypto_rng_unix.use_default ();
  established_session_survives_a_rekey ();
  kexinit_before_established_is_refused ();
  second_kexinit_during_an_exchange_is_refused ()
