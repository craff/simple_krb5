
exception Krb5_error of string
let _ = Callback.register_exception "ml_krb5_error" (Krb5_error "")

external is_thread_safe : unit -> bool = "ml_krb5_is_thread_safe"

type context

external init_context : bool -> context = "ml_krb5_init_context"
(** [init_context(secure)] initialize a krb5 context *)

type raw_principal

type principal = context * raw_principal

external free_principal : context -> raw_principal -> unit = "ml_free_krb5_principal"

external raw_parse_name : context -> string -> raw_principal = "ml_krb5_parse_name"

let mk_principal context raw =
  let r = (context, raw) in
  Gc.finalise (fun (c,r) -> free_principal c r) r;
  r

let parse_name : context:context -> string -> principal =
  fun ~context name ->
    let raw = raw_parse_name context name in
    mk_principal context raw

external raw_principal_realm : raw_principal -> string = "ml_krb5_principal_realm"
external raw_principal_data : raw_principal -> string array = "ml_krb5_principal_data"

let principal_realm(_,p) = raw_principal_realm p
let principal_data (_,p) = raw_principal_data  p

type raw_keytab

type keytab = context * raw_keytab

external kt_close : context -> raw_keytab -> unit = "ml_krb5_kt_close"

external raw_kt_resolve : context -> string option -> raw_keytab = "ml_krb5_kt_resolve"

let mk_keytab context raw =
  let r = (context, raw) in
  Gc.finalise (fun (c,r) -> kt_close c r) r;
  r

let kt_resolve ~context ?name () =
  let raw = raw_kt_resolve context name in
  mk_keytab context raw

type raw_ccache

type ccache = context * raw_ccache

external cc_close : context -> raw_ccache -> unit = "ml_krb5_cc_close"

external raw_cc_resolve : context -> string option -> raw_ccache =
  "ml_krb5_cc_resolve"

let mk_ccache context raw =
  let r = (context, raw) in
  Gc.finalise (fun (c,r) -> cc_close c r) r;
  r

let cc_resolve : context:context -> ?name:string -> unit -> ccache =
  fun ~context ?name () ->
    let raw = raw_cc_resolve context name in
    mk_ccache context raw

type raw_creds

type creds = context * raw_creds

external free_creds : context -> raw_creds -> unit = "ml_free_krb5_creds"

external raw_get_init_creds_password
         : context -> raw_principal -> string -> raw_principal option ->
           raw_keytab option -> raw_ccache option -> string option -> raw_creds
  = "ml_krb5_get_init_creds_password" "mx_krb5_get_init_creds_password"

let mk_creds context raw =
  let r = (context, raw) in
  Gc.finalise (fun (c,r) -> free_creds c r) r;
  r

let check_ctx name context (ctx, r) =
  if ctx != context then
    invalid_arg (name ^ ": context mismatch");
  r

let get_init_creds_password : ?tkt_service:string -> principal:principal -> ?server:principal -> ?keytab:keytab -> ?ccache:ccache -> string -> creds =
  fun ?tkt_service ~principal ?server ?keytab ?ccache password ->
  let (context, raw_principal) = principal in
  let chk pair = check_ctx "get_init_creds_password" context pair in
  let raw_server = Option.map chk server in
  let raw_keytab = Option.map chk keytab in
  let raw_ccache = Option.map chk ccache in
  let raw = raw_get_init_creds_password
              context raw_principal password raw_server
              raw_keytab raw_ccache tkt_service
  in
  mk_creds context raw

external raw_get_init_creds_keytab
         : context -> raw_principal -> raw_principal option ->
           raw_keytab -> raw_ccache option -> string option -> raw_creds
  = "ml_krb5_get_init_creds_keytab" "mx_krb5_get_init_creds_keytab"

let get_init_creds_keytab : ?tkt_service:string -> principal:principal -> ?server:principal -> ?ccache:ccache -> keytab -> creds =
  fun ?tkt_service ~principal ?server ?ccache keytab ->
  let (context, raw_principal) = principal in
  let chk pair = check_ctx "get_init_creds_password" context pair in
  let raw_server = Option.map chk server in
  let raw_keytab = chk keytab in
  let raw_ccache = Option.map chk ccache in
  let raw = raw_get_init_creds_keytab
              context raw_principal raw_server raw_keytab raw_ccache tkt_service
  in
  mk_creds context raw

external raw_ticket_string_from_creds : raw_creds -> string = "ml_krb5_creds_data"

let ticket_string_from_creds : creds -> string = fun creds ->
  raw_ticket_string_from_creds (snd creds)
