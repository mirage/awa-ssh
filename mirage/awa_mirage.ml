open Lwt.Infix

module Make (F : Mirage_flow.S) (T : Mirage_time.S) (M : Mirage_clock.MCLOCK) = struct

  module FLOW = F
  module MCLOCK = M

  type error  = [ `Msg of string
                | `Read of F.error
                | `Write of F.write_error ]
  type write_error = [ Mirage_flow.write_error | error ]

  let pp_error ppf = function
    | `Msg e -> Fmt.string ppf e
    | `Read e -> F.pp_error ppf e
    | `Write e -> F.pp_write_error ppf e

  let pp_write_error ppf = function
    | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
    | #error as e -> pp_error ppf e

  type flow = {
    flow : FLOW.flow ;
    mutable state : [ `Active of Awa.Client.t | `Eof | `Error of error ]
  }

  let write_flow t buf =
    FLOW.write t.flow buf >>= function
    | Ok () -> Lwt.return (Ok ())
    | Error w -> t.state <- `Error (`Write w) ; Lwt.return (Error (`Write w))

  let writev_flow t bufs =
    Lwt_list.fold_left_s (fun r d ->
        match r with
        | Error e -> Lwt.return (Error e)
        | Ok () -> write_flow t d)
      (Ok ()) bufs

  let now () =
    Mtime.of_uint64_ns (M.elapsed_ns ())

  let read_react t =
    match t.state with
    | `Eof | `Error _ -> Lwt.return (Error ())
    | `Active _ ->
      FLOW.read t.flow >>= function
      | Error e -> t.state <- `Error (`Read e) ; Lwt.return (Error ())
      | Ok `Eof -> t.state <- `Eof ; Lwt.return (Error ())
      | Ok (`Data data) ->
        match t.state with
        | `Active ssh ->
            begin match Awa.Client.incoming ssh (now ()) data with
            | Error msg -> t.state <- `Error (`Msg msg) ; Lwt.return (Error ())
            | Ok (ssh', out, events) ->
              let state' = if List.mem `Disconnected events then `Eof else `Active ssh' in
              t.state <- state';
              writev_flow t out >>= fun _ ->
              Lwt.return (Ok events)
          end
        | _ -> Lwt.return (Error ())

  let rec drain_handshake t =
    read_react t >>= function
    | Ok es ->
      begin match t.state, List.filter (function `Established _ -> true | _ -> false) es with
        | `Eof, _ -> Lwt.return (Error (`Msg "disconnected"))
        | `Error e, _ -> Lwt.return (Error e)
        | `Active _, [ `Established id ] -> Lwt.return (Ok id)
        | `Active _, _ -> drain_handshake t
      end
    | Error () -> match t.state with
      | `Error e -> Lwt.return (Error e)
      | `Eof -> Lwt.return (Error (`Msg "disconnected"))
      | `Active _ -> assert false

  let rec read t =
    read_react t >>= function
    | Ok events ->
      let r = List.fold_left (fun acc e ->
          match acc, e with
          | `Data d, `Channel_data (_, more) -> `Data (Cstruct.append d more)
            (* TODO verify that received on same channel! *)
          | `Data d, _ -> `Data d
          | `Nothing, `Channel_data (_, data) -> `Data data
          | `Nothing, `Channel_eof _ -> `Eof
          | `Nothing, `Disconnected -> `Eof
          | a, _ -> a)
          `Nothing events
      in
      begin match r with
        | `Nothing -> read t
        | `Data _ | `Eof as r -> Lwt.return (Ok r)
      end
    | Error () -> match t.state with
      | `Error e -> Lwt.return (Error e)
      | `Eof -> Lwt.return (Ok `Eof)
      | `Active _ -> assert false

  let close t =
    (* TODO ssh session teardown (send some protocol messages) *)
    FLOW.close t.flow >|= fun () ->
    t.state <- `Eof

  let writev t bufs =
    let open Lwt_result.Infix in
    match t.state with
    | `Active ssh ->
      Lwt_list.fold_left_s (fun r data ->
          match r with
          | Error e -> Lwt.return (Error e)
          | Ok ssh ->
            match Awa.Client.outgoing_data ssh data with
            | Ok (ssh', datas) ->
              t.state <- `Active ssh';
              writev_flow t datas >|= fun () ->
              ssh'
            | Error msg ->
              t.state <- `Error (`Msg msg) ;
              Lwt.return (Error (`Msg msg)))
        (Ok ssh) bufs >|= fun _ -> ()
    | `Eof -> Lwt.return (Error `Closed)
    | `Error e -> Lwt.return (Error (e :> write_error))

  let write t buf = writev t [buf]

  let client_of_flow ?authenticator ~user key req flow =
    let open Lwt_result.Infix in
    let client, msgs = Awa.Client.make ?authenticator ~user key in
    let t = {
      flow   = flow ;
      state  = `Active client ;
    } in
    writev_flow t msgs >>= fun () ->
    drain_handshake t >>= fun id ->
    (* TODO that's a bit hardcoded... *)
    let ssh = match t.state with `Active t -> t | _ -> assert false in
    (match Awa.Client.outgoing_request ssh ~id req with
     | Error msg -> t.state <- `Error (`Msg msg) ; Lwt.return (Error (`Msg msg))
     | Ok (ssh', data) -> t.state <- `Active ssh' ; write_flow t data) >|= fun () ->
    t

(* copy from awa_lwt.ml and unix references removed in favor to FLOW *)
  type nexus_msg =
    | Rekey
    | Net_eof
    | Net_io of Cstruct.t
    | Sshout of (int32 * Cstruct.t)
    | Ssherr of (int32 * Cstruct.t)

  type sshin_msg = [
    | `Data of Cstruct.t
    | `Eof
  ]

  type channel = {
    cmd         : string;
    id          : int32;
    sshin_mbox  : sshin_msg Lwt_mvar.t;
    exec_thread : unit Lwt.t;
  }

  type exec_callback =
    string ->                     (* cmd *)
    (unit -> sshin_msg Lwt.t) ->  (* sshin *)
    (Cstruct.t -> unit Lwt.t) ->  (* sshout *)
    (Cstruct.t -> unit Lwt.t) ->  (* ssherr *)
    unit Lwt.t

  type t = {
    exec_callback  : exec_callback;       (* callback to run on exec *)
    channels       : channel list;        (* Opened channels *)
    nexus_mbox     : nexus_msg Lwt_mvar.t;(* Nexus mailbox *)
  }

  let wrapr = function
    | Ok x -> Lwt.return x
    | Error e -> Lwt.fail_invalid_arg e

  let send_msg flow server msg =
    wrapr (Awa.Server.output_msg server msg)
    >>= fun (server, msg_buf) ->
    FLOW.write flow msg_buf >>= function
      | Ok () -> Lwt.return server
      | Error w ->
        Logs.err (fun m -> m "error %a while writing" FLOW.pp_write_error w);
        Lwt.return server

  let rec send_msgs fd server = function
    | msg :: msgs ->
      send_msg fd server msg
      >>= fun server ->
      send_msgs fd server msgs
    | [] -> Lwt.return server

  let net_read flow =
    FLOW.read flow >>= function
    | Error e ->
      Logs.err (fun m -> m "read error %a" FLOW.pp_error e);
      Lwt.return Net_eof
    | Ok `Eof ->
      Lwt.return Net_eof
    | Ok (`Data data) ->
      let n = Cstruct.length data in
      assert (n >= 0); (* handle exception ! ! *)
      let () = assert (n > 0) in          (* XXX *)
      Lwt.return (Net_io data)

  let sshin_eof c =
    Lwt_mvar.put c.sshin_mbox `Eof

  let sshin_data c data =
    Lwt_mvar.put c.sshin_mbox (`Data data)

  let lookup_channel t id =
    List.find_opt (fun c -> id = c.id) t.channels

  let rec nexus t fd server input_buffer =
    wrapr (Awa.Server.pop_msg2 server input_buffer)
    >>= fun (server, msg, input_buffer) ->
    match msg with
    | None -> (* No SSH msg *)
      Lwt.catch
        (fun () ->
          let timeout = T.sleep_ns 2000000000L >>= fun () -> Lwt.return Rekey in
          Lwt.pick [ Lwt_mvar.take t.nexus_mbox ;
                      net_read fd ;
                      timeout ])
      (function exn -> Lwt.fail exn)
      >>= fun nexus_msg ->
      (match nexus_msg with
        | Rekey ->
          (match Awa.Server.maybe_rekey server (now ()) with
          | None -> nexus t fd server input_buffer
          | Some (server, kexinit) ->
            send_msg fd server kexinit
            >>= fun server ->
            nexus t fd server input_buffer)
       | Net_eof ->
         Lwt.return t
       | Net_io buf -> nexus t fd server (Awa.Util.cs_join input_buffer buf)
       | Sshout (id, buf) | Ssherr (id, buf) ->
         wrapr (Awa.Server.output_channel_data server id buf)
         >>= fun (server, msgs) ->
         send_msgs fd server msgs >>= fun server ->
         nexus t fd server input_buffer)
    | Some msg -> (* SSH msg *)
      wrapr (Awa.Server.input_msg server msg (now ()))
      >>= fun (server, replies, event) ->
      send_msgs fd server replies
      >>= fun server ->
      match event with
      | None -> nexus t fd server input_buffer
      | Some Awa.Server.Disconnected _ ->
        Lwt_list.iter_p sshin_eof t.channels
        >>= fun () ->
        Lwt.return t
      | Some Awa.Server.Channel_eof id ->
        (match lookup_channel t id with
         | Some c -> sshin_eof c >>= fun () -> Lwt.return t
         | None -> Lwt.return t)
      | Some Awa.Server.Channel_data (id, data) ->
        (match lookup_channel t id with
         | Some c -> sshin_data c data
         | None -> Lwt.return_unit)
        >>= fun () ->
        nexus t fd server input_buffer
      | Some Awa.Server.Channel_subsystem (id, cmd) (* same as exec *)
      | Some Awa.Server.Channel_exec (id, cmd) ->
        (* Create an input box *)
        let sshin_mbox = Lwt_mvar.create_empty () in
        (* Create a callback for each mbox *)
        let sshin () = Lwt_mvar.take sshin_mbox in
        let sshout id buf = Lwt_mvar.put t.nexus_mbox (Sshout (id, buf)) in
        let ssherr id buf = Lwt_mvar.put t.nexus_mbox (Ssherr (id, buf)) in
        (* Create the execution thread *)
        let exec_thread = t.exec_callback cmd sshin (sshout id) (ssherr id) in
        let c = { cmd; id; sshin_mbox; exec_thread } in
        let t = { t with channels = c :: t.channels } in
        nexus t fd server input_buffer

  let spawn_server server msgs fd exec_callback =
    let t = { exec_callback;
              channels = [];
              nexus_mbox = Lwt_mvar.create_empty () }
    in
    send_msgs fd server msgs >>= fun server ->
    nexus t fd server (Cstruct.create 0)

end
