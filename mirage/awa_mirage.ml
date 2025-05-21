open Lwt.Infix

let src = Logs.Src.create "awa.mirage" ~doc:"Awa mirage"
module Log = (val Logs.src_log src : Logs.LOG)

module Auth = struct
  type user = {
    name     : string;
    password : string option;
    keys     : Awa.Hostkey.pub list;
  }

  type db = user list

  let make_user name ?password keys =
    if password = None && keys = [] then
      invalid_arg "password must be Some, and/or keys must not be empty";
    { name; password; keys }

  let lookup_user name db =
    List.find_opt (fun user -> user.name = name) db

  let verify db user userauth =
    match lookup_user user db, userauth with
    | None, Awa.Server.Pubkey pubkeyauth ->
      Awa.Server.verify_pubkeyauth ~user pubkeyauth && false
    | (None | Some { password = None; _ }), Awa.Server.Password _ -> false
    | Some u, Awa.Server.Pubkey pubkeyauth ->
      Awa.Server.verify_pubkeyauth ~user pubkeyauth &&
      List.exists (fun pubkey -> Awa.Hostkey.pub_eq pubkey pubkeyauth.pubkey) u.keys
    | Some { password = Some password; _ }, Awa.Server.Password password' ->
      let open Digestif.SHA256 in
      let a = digest_string password
      and b = digest_string password' in
      Digestif.SHA256.equal a b
end

module Make (F : Mirage_flow.S) = struct
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

  (* this is the flow of a ssh-client. be aware that we're only using a single
     channel.

     the state `Read_closed is set (a) when a TCP.read returned `Eof,
     and (b) when the application did a shutdown `read (or `read_write).
     the state `Write_closed is set (a) when a TCP.write returned `Closed,
     and (b) when the application did a shutdown `write (or `read_write).

     If we're in `Write_closed, and do a shutdown `read, we'll end up in
     `Closed, and attempt to (a) send a SSH_MSG_CHANNEL_CLOSE and (b) TCP.close.
     This may fail, since on the TCP layer, the connection may have already be
     half-closed (or fully closed) in the write direction. We ignore this error
     from writev below in close.
  *)
  type flow = {
    flow : F.flow ;
    mutable state : [
      | `Active of Awa.Client.t
      | `Read_closed of Awa.Client.t
      | `Write_closed of Awa.Client.t
      | `Closed
      | `Error of error ]
  }

  let half_close state mode =
    match state, mode with
    | `Active ssh, `read -> `Read_closed ssh
    | `Active ssh, `write -> `Write_closed ssh
    | `Active _, `read_write -> `Closed
    | `Read_closed ssh, `read -> `Read_closed ssh
    | `Read_closed _, (`write | `read_write) -> `Closed
    | `Write_closed ssh, `write -> `Write_closed ssh
    | `Write_closed _, (`read | `read_write) -> `Closed
    | (`Closed | `Error _) as e, (`read | `write | `read_write) -> e

  let inject_state ssh = function
    | `Active _ -> `Active ssh
    | `Read_closed _ -> `Read_closed ssh
    | `Write_closed _ -> `Write_closed ssh
    | (`Closed | `Error _) as e -> e

  let write_flow t buf =
    F.write t.flow buf >>= function
    | Ok _ as o -> Lwt.return o
    | Error `Closed ->
      Log.warn (fun m -> m "error closed while writing");
      t.state <- half_close t.state `write;
      Lwt.return (Error (`Write `Closed))
    | Error w ->
      Log.warn (fun m -> m "error %a while writing" F.pp_write_error w);
      t.state <- `Error (`Write w);
      Lwt.return (Error (`Write w))

  let writev_flow t bufs =
    Lwt_list.fold_left_s (fun r d ->
        match r with
        | Error _ as e -> Lwt.return e
        | Ok () -> write_flow t d)
      (Ok ()) bufs

  let now () = Mtime.of_uint64_ns (Mirage_mtime.elapsed_ns ())

  let read_react t =
    match t.state with
    | `Read_closed _ | `Closed | `Error _ -> Lwt.return (Error ())
    | `Active _ | `Write_closed _ ->
      F.read t.flow >>= function
      | Error e ->
        Log.warn (fun m -> m "error %a while reading" F.pp_error e);
        t.state <- `Error (`Read e);
        Lwt.return (Error ())
      | Ok `Eof ->
        t.state <- half_close t.state `read;
        Lwt.return (Error ())
      | Ok (`Data data) ->
        match t.state with
        | `Active ssh | `Write_closed ssh ->
            begin match Awa.Client.incoming ssh (now ()) data with
            | Error msg ->
              Log.warn (fun m -> m "error %s while processing data" msg);
              t.state <- `Error (`Msg msg);
              Lwt.return (Error ())
            | Ok (ssh', out, events) ->
              t.state <-
                inject_state ssh' (if List.mem `Disconnected events then half_close t.state `read else t.state);
              writev_flow t out >>= fun _ ->
              Lwt.return (Ok events)
          end
        | _ -> Lwt.return (Error ())

  let rec drain_handshake t =
    read_react t >>= function
    | Ok es ->
      begin match t.state, List.filter (function `Established _ -> true | _ -> false) es with
        | (`Read_closed _ | `Closed), _ -> Lwt.return (Error (`Msg "disconnected"))
        | `Error e, _ -> Lwt.return (Error e)
        | (`Active _ | `Write_closed _), [ `Established id ] -> Lwt.return (Ok id)
        | (`Active _ | `Write_closed _), _ -> drain_handshake t
      end
    | Error () -> match t.state with
      | `Error e -> Lwt.return (Error e)
      | `Closed | `Read_closed _ | `Active _ | `Write_closed _ -> Lwt.return (Error (`Msg "disconnected"))

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
          | a, `Channel_stderr (id, data) ->
            Log.warn (fun m -> m "%ld stderr %s" id (Cstruct.to_string data));
            a
          | a, _ -> a)
          `Nothing events
      in
      begin match r with
        | `Nothing -> read t
        | `Data _ | `Eof as r -> Lwt.return (Ok r)
      end
    | Error () -> match t.state with
      | `Error e -> Lwt.return (Error e)
      | `Closed | `Read_closed _ | `Active _ | `Write_closed _ -> Lwt.return (Ok `Eof)

  let close t =
    (match t.state with
     | `Active ssh | `Read_closed ssh | `Write_closed ssh ->
       let ssh, msg = Awa.Client.close ssh in
       t.state <- inject_state ssh t.state;
       t.state <- `Closed;
       (* as outlined above, this may fail since the TCP flow may already be (half-)closed *)
       writev_flow t (Option.to_list msg) >|= ignore
     | `Error _ | `Closed -> Lwt.return_unit) >>= fun () ->
    F.close t.flow

  let shutdown t mode =
    match t.state with
    | `Active ssh | `Read_closed ssh | `Write_closed ssh ->
      let ssh, msgs =
        match t.state, mode with
        | (`Active ssh | `Read_closed ssh), `write -> Awa.Client.eof ssh
        | _, `read_write ->
          Awa.Client.close ssh |> fun (t, msg) -> t, Option.to_list msg
        | _ -> ssh, []
      in
      t.state <- inject_state ssh (half_close t.state mode);
      (* as outlined above, this may fail since the TCP flow may already be (half-)closed *)
      writev_flow t msgs >>= fun _ ->
      (* we don't [FLOW.shutdown _ mode] because we still need to read/write
         channel_eof/channel_close unless both directions are closed *)
      (match t.state with
       | `Closed -> F.close t.flow
       | _ -> Lwt.return_unit)
    | `Error _ | `Closed ->
      F.close t.flow

  let writev t bufs =
    let open Lwt_result.Infix in
    match t.state with
    | `Active ssh | `Read_closed ssh ->
      Lwt_list.fold_left_s (fun r data ->
          match r with
          | Error e -> Lwt.return (Error e)
          | Ok ssh ->
            match Awa.Client.outgoing_data ssh data with
            | Ok (ssh', datas) ->
              t.state <- inject_state ssh' t.state;
              writev_flow t datas >|= fun () ->
              ssh'
            | Error msg ->
              t.state <- `Error (`Msg msg) ;
              Lwt.return (Error (`Msg msg)))
        (Ok ssh) bufs >|= fun _ -> ()
    | `Write_closed _ | `Closed -> Lwt.return (Error `Closed)
    | `Error e -> Lwt.return (Error (e :> write_error))

  let write t buf = writev t [buf]

  let client_of_flow ?authenticator ~user auth req flow =
    let open Lwt_result.Infix in
    let client, msgs = Awa.Client.make ?authenticator ~user auth in
    let t = {
      flow   = flow ;
      state  = `Active client ;
    } in
    writev_flow t msgs >>= fun () ->
    drain_handshake t >>= fun id ->
    match t.state with
    | `Active ssh ->
      (match Awa.Client.outgoing_request ssh ~id req with
       | Error msg -> t.state <- `Error (`Msg msg) ; Lwt.return (Error (`Msg msg))
       | Ok (ssh', data) -> t.state <- `Active ssh' ; write_flow t data) >|= fun () ->
      t
    | `Read_closed _ -> Lwt.return (Error (`Msg "read closed"))
    | `Write_closed _ -> Lwt.return (Error (`Msg "write closed"))
    | `Closed -> Lwt.return (Error (`Msg "closed"))
    | `Error e -> Lwt.return (Error e)


(* copy from awa_lwt.ml and unix references removed in favor to FLOW *)
  type nexus_msg =
    | Rekey
    | Net_eof
    | Net_io of Cstruct.t
    | Sshout of (int32 * Cstruct.t)
    | Ssherr of (int32 * Cstruct.t)

  type channel = {
    cmd         : string option;
    id          : int32;
    sshin_mbox  : Cstruct.t Mirage_flow.or_eof Lwt_mvar.t;
    exec_thread : unit Lwt.t;
  }

  type request =
    | Pty_req of { width : int32; height : int32; max_width : int32; max_height : int32; term : string }
    | Pty_set of { width : int32; height : int32; max_width : int32; max_height : int32 }
    | Set_env of { key : string; value : string }
    | Channel of { cmd : string
                 ; ic : unit -> Cstruct.t Mirage_flow.or_eof Lwt.t
                 ; oc : Cstruct.t -> unit Lwt.t
                 ; ec : Cstruct.t -> unit Lwt.t }
     | Shell  of { ic : unit -> Cstruct.t Mirage_flow.or_eof Lwt.t
                 ; oc : Cstruct.t -> unit Lwt.t
                 ; ec : Cstruct.t -> unit Lwt.t }

  type exec_callback = request -> unit Lwt.t

  type t = {
    user_db : Auth.db;
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
    F.write flow msg_buf >>= function
      | Ok () -> Lwt.return server
      | Error w ->
        Log.err (fun m -> m "error %a while writing" F.pp_write_error w);
        Lwt.return server

  let rec send_msgs fd server = function
    | msg :: msgs ->
      send_msg fd server msg
      >>= fun server ->
      send_msgs fd server msgs
    | [] -> Lwt.return server

  let net_read flow =
    F.read flow >>= function
    | Error e ->
      Log.err (fun m -> m "read error %a" F.pp_error e);
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

  let rekey_promise server =
    match server.Awa.Server.key_eol with
    | None -> []
    | Some mtime ->
      [ Mirage_sleep.ns (Mtime.to_uint64_ns mtime) >>= fun () -> Lwt.return Rekey ]

  let rec nexus t fd server input_buffer pending_promises =
    wrapr (Awa.Server.pop_msg2 server input_buffer)
    >>= fun (server, msg, input_buffer) ->
    match msg with
    | None -> (* No SSH msg *)
      (* We will listen from two incomming messages sources, from the net interface with
       * 'net_read', and from the ssh server with 'Lwt_mvar.take'. To let the promises
       * to be resolved, we use Lwt.choose to not add another of these until we know
       * that it was fulfiled.
      *)
      Lwt.nchoose_split pending_promises >>= fun (nexus_msg_fulfiled, pending_promises) ->
      (* We need to keep track of the "not fulfiled" promises and only Lwt.nchoose_split
       * allows us to have this information. This function also gives us a list of
       * "already fulfiled" promises. Here we consume this list and add the relevant new
       * promises to watch.
       *)
      let rec loop t fd server input_buffer fulfiled_promises pending_promises =
        match fulfiled_promises with
        | [] -> nexus t fd server input_buffer pending_promises
        (* Here we have the timeout fulfiled, we can let the net_read + Lwt_mvar.take continue *)
        | Rekey :: remaining_fulfiled_promises ->
          (match Awa.Server.maybe_rekey server (now ()) with
          | None -> loop t fd server input_buffer remaining_fulfiled_promises pending_promises
          | Some (server, kexinit) ->
            send_msg fd server kexinit
            >>= fun server ->
            loop t fd server input_buffer remaining_fulfiled_promises (pending_promises @ rekey_promise server)
          )
        (* Here we have the net_read tells us to stop the communication... *)
        | Net_eof :: _ -> Lwt.return t
        (* Here we have the net_read fulfiled, we can let the timeout + Lwt_mvar.take continue and add a new net_read *)
        | Net_io buf :: remaining_fulfiled_promises ->
          loop t fd server (Awa.Util.cs_join input_buffer buf) remaining_fulfiled_promises (List.append pending_promises [net_read fd])
        (* Here we have the Lwt_mvar.take fulfiled, we can let the timeout + net_read continue and add a new Lwt_mvar.take *)
        | Sshout (id, buf) :: remaining_fulfiled_promises
        | Ssherr (id, buf) :: remaining_fulfiled_promises ->
          wrapr (Awa.Server.output_channel_data server id buf)
          >>= fun (server, msgs) ->
          send_msgs fd server msgs >>= fun server ->
          loop t fd server input_buffer remaining_fulfiled_promises (List.append pending_promises [ Lwt_mvar.take t.nexus_mbox ])
      in
      loop t fd server input_buffer nexus_msg_fulfiled pending_promises
    (* In all of the following we have the Lwt_mvar.take fulfiled, we can let the timeout + net_read continue
     * and add a new Lwt_mvar.take *)
    | Some msg -> (* SSH msg *)
      wrapr (Awa.Server.input_msg server msg (now ()))
      >>= fun (server, replies, event) ->
      send_msgs fd server replies
      >>= fun server ->
      match event with
      | None -> nexus t fd server input_buffer (List.append pending_promises [ Lwt_mvar.take t.nexus_mbox ])
      | Some Awa.Server.Userauth (user, userauth) ->
        let accept = Auth.verify t.user_db user userauth in
        (* FIXME: Result.get_ok: Awa.Server.{accept,reject}_userauth should likely raise instead *)
        let server, reply =
          Result.get_ok
            (if accept then
               Awa.Server.accept_userauth server userauth ()
             else
               Awa.Server.reject_userauth server userauth)
        in
        send_msg fd server reply >>= fun server ->
        nexus t fd server input_buffer pending_promises
      | Some Awa.Server.Pty (term, width, height, max_width, max_height, _modes) ->
        t.exec_callback (Pty_req { width; height; max_width; max_height; term; }) >>= fun () ->
        nexus t fd server input_buffer pending_promises
      | Some Awa.Server.Pty_set (width, height, max_width, max_height) ->
        t.exec_callback (Pty_set { width; height; max_width; max_height }) >>= fun () ->
        nexus t fd server input_buffer pending_promises
      | Some Awa.Server.Set_env (key, value) ->
        t.exec_callback (Set_env { key; value; }) >>= fun () ->
        nexus t fd server input_buffer pending_promises
      | Some Awa.Server.Disconnected _ ->
        Lwt_list.iter_p sshin_eof t.channels
        >>= fun () -> Lwt.return t
      | Some Awa.Server.Channel_eof id ->
        (match lookup_channel t id with
         | Some c -> sshin_eof c >>= fun () -> Lwt.return t
         | None -> Lwt.return t)
      | Some Awa.Server.Channel_data (id, data) ->
        (match lookup_channel t id with
         | Some c -> sshin_data c data
         | None -> Lwt.return_unit)
        >>= fun () ->
        nexus t fd server input_buffer (List.append pending_promises [ Lwt_mvar.take t.nexus_mbox ])
      | Some Awa.Server.Channel_subsystem (id, cmd) (* same as exec *)
      | Some Awa.Server.Channel_exec (id, cmd) ->
        (* Create an input box *)
        let sshin_mbox = Lwt_mvar.create_empty () in
        (* Create a callback for each mbox *)
        let ic () = Lwt_mvar.take sshin_mbox in
        let oc id buf = Lwt_mvar.put t.nexus_mbox (Sshout (id, buf)) in
        let ec id buf = Lwt_mvar.put t.nexus_mbox (Ssherr (id, buf)) in
        (* Create the execution thread *)
        let exec_thread = t.exec_callback (Channel { cmd; ic; oc= oc id; ec= ec id; }) in
        let c = { cmd= Some cmd; id; sshin_mbox; exec_thread } in
        let t = { t with channels = c :: t.channels } in
        nexus t fd server input_buffer (List.append pending_promises [ Lwt_mvar.take t.nexus_mbox ])
      | Some (Awa.Server.Start_shell id) ->
        let sshin_mbox = Lwt_mvar.create_empty () in
        (* Create a callback for each mbox *)
        let ic () = Lwt_mvar.take sshin_mbox in
        let oc id buf = Lwt_mvar.put t.nexus_mbox (Sshout (id, buf)) in
        let ec id buf = Lwt_mvar.put t.nexus_mbox (Ssherr (id, buf)) in
        (* Create the execution thread *)
        let exec_thread = t.exec_callback (Shell { ic; oc= oc id; ec= ec id; }) in
        let c = { cmd= None; id; sshin_mbox; exec_thread } in
        let t = { t with channels = c :: t.channels } in
        nexus t fd server input_buffer (List.append pending_promises [ Lwt_mvar.take t.nexus_mbox ])

  let spawn_server ?stop server user_db msgs fd exec_callback =
    let t = { user_db;
              exec_callback;
              channels = [];
              nexus_mbox = Lwt_mvar.create_empty ()
            }
    in
    let open Lwt.Syntax in
    let* switched_off =
      let thread, u = Lwt.wait () in
      Lwt_switch.add_hook_or_exec stop (fun () ->
        Lwt.wakeup_later u Net_eof;
        Lwt_list.iter_p sshin_eof t.channels) >|= fun () -> thread in
    send_msgs fd server msgs >>= fun server ->
    (* the ssh communication will start with 'net_read' and can only add a 'Lwt.take' promise when
     * one Awa.Server.Channel_{exec,subsystem} is received
     *)
    nexus t fd server (Cstruct.create 0) ([ switched_off; net_read fd ] @ rekey_promise server)

end
