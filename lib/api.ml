(* This Source Code Form is subject to the terms of the Mozilla Public License,
   v. 2.0. If a copy of the MPL was not distributed with this file, You can
   obtain one at https://mozilla.org/MPL/2.0/ *)

open Opium
open Str

(** Bind dependencies *)

module Connection = (val Infra.Database.connect ())

module PostgresRepository = Repository.Member (Connection)
module MemberService = Service.Member (PostgresRepository)

let set_logger () =
  Logs.set_reporter (Logs_fmt.reporter ()) ;
  Logs.set_level Infra.Environment.log_level


let print_error msg = `Assoc [ ("error_message", `String msg) ] |> Yojson.Basic.pretty_to_string

let json_response ~status ~body = Response.make ~status ~body ~headers:(Httpaf.Headers.of_list 
  [
    ("Content-Type", "application/json");
    ("Access-Control-Allow-Origin", "http://localhost:3006");
    ("Access-Control-Allow-Headers", "content-type");
    ("Access-Control-Allow-Headers", "authorization");
    ("Access-Control-Allow-Methods", "PUT, POST, GET, OPTIONS, DELETE")
  ]
)


(** Heartbeat route *)
let root req =
  let open Lwt in
    let body = `Assoc [ ("status", `String "CORS setter")] |> Yojson.Basic.pretty_to_string in
      json_response ~status:`OK ~body:(Body.of_string body) ()
      |> Lwt.return

let handle_options req = 
  let open Lwt in
    let body = `Assoc [ ("status", `String "all fine")] |> Yojson.Basic.pretty_to_string in
      json_response ~status:`OK ~body:(Body.of_string body) ()
      |> Lwt.return



(** Testing purpose route *)
let echo req =
  let open Lwt in
  req
  |> Request.to_json
  >>= fun json ->
  let body = Option.get json |> Yojson.Safe.to_string |> Body.of_string in
  json_response ~status:`OK ~body () |> Lwt.return


(** Singnup route *)
let signup req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> json_response ~status:`Bad_request ~body:(Body.of_string (print_error "There is no JSON body")) () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let email = json |> member "email" |> to_string
      and password = json |> member "password" |> to_string 
      and confirmPassword = json |> member "confirmPassword" |> to_string in 
      if (Bool.not (String.equal password confirmPassword)) then
        json_response ~status:`Forbidden ~body:(Body.of_string (print_error "Passwords don't match")) ()
          |> Lwt.return
      else 
        if ((String.length password) < 7) then 
          json_response ~status:`Forbidden ~body:(Body.of_string (print_error "Password must have a length of 7 or more")) ()
          |> Lwt.return
        else
          MemberService.signup ~email ~password
          >>= (function
          | Error e ->
              json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
              |> Lwt.return
          | Ok _ -> 
            let body = `Assoc [ ("status", `String "Signed up")] |> Yojson.Basic.pretty_to_string |> Body.of_string in
            json_response ~status:`Created ~body () |> Lwt.return)


(** Singnin route *)
let signin req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> json_response ~status:`Bad_request ~body:(Body.of_string (print_error "There is no JSON body")) () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let email = json |> member "email" |> to_string
      and password = json |> member "password" |> to_string in
      MemberService.signin ~email ~password
      >>= (function
      | Error e ->
          json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
          |> Lwt.return
      | Ok jwt ->
          ( match jwt with
          | Error e ->
              json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
              |> Lwt.return
          | Ok jwt_string ->
            let body = `Assoc [ ("jwt", `String jwt_string)] |> Yojson.Basic.pretty_to_string |> Body.of_string in
              json_response ~status:`OK ~body ()
              |> Lwt.return ))


(** Jwt verification route *)

let verify req =
  let open Lwt in
  req
  |> Request.to_json
  >>= function
  | None -> json_response ~status:`Bad_request ~body:(Body.of_string (print_error "There is no JSON body")) () |> Lwt.return
  | Some json ->
      let open Yojson.Safe.Util in
      let jwt = json |> member "jwt" |> to_string in
      ( match Service.Jwt.verify_and_get_iss jwt with
      | Error e ->
          json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
          |> Lwt.return
      | Ok iss ->
        let body = `Assoc [ ("user_id", `String iss)] |> Yojson.Basic.pretty_to_string |> Body.of_string in
          json_response ~status:`OK ~body () |> Lwt.return
      )

let get_member req = 
  let open Lwt in
    (
      match (Request.header "Authorization" req) with
        | None -> json_response ~status:`Forbidden ~body:(Body.of_string (print_error "There is no Authorization header")) () |> Lwt.return
        | Some authorization -> 
          let jwt = Str.string_after authorization 7 in
          (
            match Service.Jwt.verify_and_get_iss jwt with
            | Error e -> 
                json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
                |> Lwt.return
            | Ok iss ->
              let id = Router.param req "id" in
              let matching_ids = id = iss in
              (
                match matching_ids with
                | false -> json_response ~status:`Forbidden ~body:(Body.of_string (print_error "You are not the right user")) () |> Lwt.return
                | true ->
                MemberService.get_by_id ~id:id >>= 
                (function
                  | Error e ->
                    json_response ~status:`Bad_request ~body:(Body.of_string (print_error e)) ()
                    |> Lwt.return
                  | Ok member -> 
                    json_response ~status: `OK ~body:(Body.of_string (Yojson.Basic.pretty_to_string member)) ()
                    |> Lwt.return
                )
              )
          )
    )

let delete_member req = 
  let open Lwt in
  (
    match (Request.header "Authorization" req) with
        | None -> json_response ~status:`Forbidden ~body:(Body.of_string (print_error "There is no Authorization header")) () |> Lwt.return
        | Some authorization -> 
          let jwt = Str.string_after authorization 7 in
          (
            match Service.Jwt.verify_and_get_iss jwt with
            | Error e -> 
                json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
                |> Lwt.return
            | Ok iss ->
              let id = Router.param req "id" in
              let matching_ids = id = iss in
              (
                match matching_ids with
                | false -> json_response ~status:`Forbidden ~body:(Body.of_string (print_error "You are not the right user")) () |> Lwt.return
                | true ->
                MemberService.delete_by_id ~id:id >>= 
                (function
                  | Error e ->
                    json_response ~status:`Bad_request ~body:(Body.of_string (print_error e)) ()
                    |> Lwt.return
                  | Ok member -> 
                    let body = `Assoc [ ("status", `String "Deleted")] |> Yojson.Basic.pretty_to_string |> Body.of_string in
                    json_response ~status:`No_content ~body ()
                    |> Lwt.return
                )
              )
          )
  )

let update_member req =
  let open Lwt in
  (
    match (Request.header "Authorization" req) with
        | None -> json_response ~status:`Forbidden ~body:(Body.of_string (print_error "There is no Authorization header")) () |> Lwt.return
        | Some authorization -> 
          let jwt = Str.string_after authorization 7 in
          (
            match Service.Jwt.verify_and_get_iss jwt with
            | Error e -> 
                json_response ~status:`Forbidden ~body:(Body.of_string (print_error e)) ()
                |> Lwt.return
            | Ok iss ->
              let id = Router.param req "id" in
              let matching_ids = id = iss in
              (
                match matching_ids with
                | false -> json_response ~status:`Forbidden ~body:(Body.of_string "You are not the right user") () |> Lwt.return
                | true ->
                  req
                  |> Request.to_json
                  >>= function
                  | None -> json_response ~status:`Bad_request ~body:(Body.of_string (print_error "There is no JSON body")) () |> Lwt.return
                  | Some json ->
                      let open Yojson.Safe.Util in
                      let email = json |> member "email" |> to_string
                      and password = json |> member "password" |> to_string 
                      and username = json |> member "username" |> to_string in
                        MemberService.update_by_id ~email ~password ~username ~id >>= 
                        (function
                          | Error e ->
                            json_response ~status:`Bad_request ~body:(Body.of_string (print_error e)) ()
                            |> Lwt.return
                          | Ok member -> 
                            let body = `Assoc [ ("status", `String "Updated")] |> Yojson.Basic.pretty_to_string |> Body.of_string in
                              json_response ~status:`No_content ~body ()
                              |> Lwt.return
                        )
              )
          )
  )

let routes =
  [ App.get "/" root
  ; App.post "/echo" echo
  ; App.post "/signup" signup
  ; App.post "/signin" signin
  ; App.post "/verify" verify
  ; App.get "/member/:id" get_member
  ; App.delete "/member/:id" delete_member
  ; App.put "/member/:id" update_member 
  ; App.options "/**" handle_options 
  ]


let add_routes app = List.fold_left (fun app route -> route app) app routes
