open Lwt

module Make (F : Mirage_flow_lwt.S) (M : Mirage_clock.MCLOCK) = struct

  module FLOW = F

  type error  = [ `Msg of string
                | `Read of F.error
                | `Write of F.write_error ]
  type write_error = [ Mirage_flow.write_error | error ]

  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t

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
          begin match Awa.Client.incoming ssh (Mtime.of_uint64_ns (M.elapsed_ns ())) data with
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

  let close _ =
    Logs.err (fun m -> m "ignoring close for now");
    Lwt.return_unit

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

  let client_of_flow user key hostkey req flow =
    let open Lwt_result.Infix in
    let client, msgs = Awa.Client.make user key hostkey () in
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
end
