#include <stdlib.h>
#include <stdio.h>
#include <krb5/krb5.h>
#include <string.h>
#include <caml/misc.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/config.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/threads.h>
#include <caml/version.h>
#include <caml/custom.h>

// miscellaneous

CAMLprim value ml_krb5_is_thread_safe()
{
  CAMLparam0();

  CAMLreturn(Val_bool(krb5_is_thread_safe()));
}

void krb5_check_error(krb5_context context, krb5_error_code error) {
  if (error) {
    const char* msg = krb5_get_error_message(context, error);
    value v = caml_copy_string(msg);
    krb5_free_error_message(context,msg);
    caml_raise_with_arg(*caml_named_value("ml_krb5_error"),v);
  }
}

const value ml_krb5_string_data(krb5_data d) {
  return(caml_copy_string(d.data));
}

// context

#define Context_val(v) (*(krb5_context*) Data_custom_val(v))

void custom_finalize_krb5_context(value v) {
  krb5_free_context(Context_val(v));
}

static struct custom_operations krb5_context_ops = {
  "ml.krb5.context",
  custom_finalize_krb5_context,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

CAMLprim value ml_krb5_init_context(value safe)
{
  CAMLparam1(safe);
  krb5_error_code r;
  krb5_context context;
  if (Bool_val(safe)) {
    r = krb5_init_secure_context(&context);
  } else {
    r = krb5_init_context(&context);
  }
  krb5_check_error(context,r);
  value v = caml_alloc_custom(&krb5_context_ops, sizeof(krb5_context), 0, 1);
  Context_val(v) = context;
  CAMLreturn(v);
}

// principal

#define Principal_val(v) (*(krb5_principal*) Data_custom_val(v))

CAMLprim void ml_free_krb5_principal(value context, value princ) {
  CAMLparam2(context,princ);
  krb5_free_principal(Context_val(context),Principal_val(princ));
  CAMLreturn0;
}

static struct custom_operations krb5_principal_ops = {
  "ml.krb5.principal",
  custom_finalize_default, // freeing principal requires the original context
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

CAMLprim value ml_krb5_parse_name(value context, value name)
{
  CAMLparam2(context,name);
  krb5_principal princ;
  krb5_error_code r = krb5_parse_name(Context_val(context),String_val(name),&princ);
  krb5_check_error(Context_val(context),r);
  value v = caml_alloc_custom(&krb5_principal_ops, sizeof(krb5_principal), 0, 1);
  Principal_val(v) = princ;
  CAMLreturn(v);
}

CAMLprim value ml_krb5_principal_realm(value principal) {
  CAMLparam1(principal);
  CAMLreturn(ml_krb5_string_data(Principal_val(principal)->realm));
}

CAMLprim value ml_krb5_principal_data(value principal) {
  CAMLparam1(principal);
  krb5_int32 len = Principal_val(principal)->length;
  value r = caml_alloc(len, 0);
  for (krb5_int32 i = 0; i < len; i++) {
    value d = ml_krb5_string_data(Principal_val(principal)->data[i]);
    caml_modify(&Field(r, i),d);
  }
  CAMLreturn(r);
}

// keytab

#define Keytab_val(v) (*(krb5_keytab*) Data_custom_val(v))

CAMLprim void ml_krb5_kt_close(value context, value keytab) {
  CAMLparam2(context,keytab);
  krb5_kt_close(Context_val(context),Keytab_val(keytab));
  CAMLreturn0;
}

static struct custom_operations krb5_keytab_ops = {
  "ml.krb5.keytab",
  custom_finalize_default, // freeing keytab requires the original context
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

CAMLprim value ml_krb5_kt_resolve(value context, value name) {
  CAMLparam2(context,name);
  krb5_keytab keytab;
  krb5_error_code r;
  if (Is_none(name))
    r = krb5_kt_default(Context_val(context), &keytab);
  else
    r = krb5_kt_resolve(Context_val(context), String_val(Some_val(name)),&keytab);
  krb5_check_error(Context_val(context),r);
  value v = caml_alloc_custom(&krb5_keytab_ops, sizeof(krb5_keytab), 0, 1);
  Keytab_val(v) = keytab;
  CAMLreturn(v);
}

// credentials cache

#define Ccache_val(v) (*(krb5_ccache*) Data_custom_val(v))

CAMLprim void ml_krb5_cc_close(value context, value keytab) {
  CAMLparam2(context,keytab);
  krb5_cc_close(Context_val(context),Ccache_val(keytab));
  CAMLreturn0;
}

static struct custom_operations krb5_ccache_ops = {
  "ml.krb5.keytab",
  custom_finalize_default, // freeing ccache requires the original context
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

CAMLprim value ml_krb5_cc_resolve(value context, value name) {
  CAMLparam2(context,name);
  krb5_ccache cc;
  krb5_error_code r;
  if (Is_none(name))
    r = krb5_cc_default(Context_val(context), &cc);
  else
    r = krb5_cc_resolve(Context_val(context), String_val(Some_val(name)),&cc);
  krb5_check_error(Context_val(context),r);
  value v = caml_alloc_custom(&krb5_ccache_ops, sizeof(krb5_ccache), 0, 1);
  Ccache_val(v) = cc;
  CAMLreturn(v);
}


// credentials

// creds val is most often used as a pointer. We don't do the indirection
// in the macro
#define Creds_val(v) ((krb5_creds*) Data_custom_val(v))

CAMLprim void ml_free_krb5_creds(value context, value creds) {
  CAMLparam2(context,creds);
  krb5_free_cred_contents(Context_val(context),Creds_val(creds));
  CAMLreturn0;
}

static struct custom_operations krb5_creds_ops = {
  "ml.krb5.creds",
  custom_finalize_default, // freeing credentials requires the original context
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

CAMLprim value mx_krb5_get_init_creds_password(value context,
					       value principal,
					       value password,
					       value server,
					       value keytab,
					       value ccache,
					       value tkt_service) {
  CAMLparam5(context,principal,password,server,keytab);
  CAMLxparam2(ccache,tkt_service);
  krb5_creds creds;
  const char* tkt = NULL;
  if (Is_some(tkt_service)) tkt = String_val(Some_val(tkt_service));
  krb5_principal serv = NULL;
  if (Is_some(server)) serv = Principal_val(Some_val(server));
  krb5_keytab kt = NULL;
  if (Is_some(keytab)) kt = Keytab_val(Some_val(keytab));
  krb5_ccache cc = NULL;
  if (Is_some(ccache)) cc = Ccache_val(Some_val(ccache));

  krb5_error_code r = krb5_get_init_creds_password(Context_val(context),
						   &creds,
						   Principal_val(principal),
						   String_val(password),
						   NULL, NULL, 0, tkt, NULL);
  krb5_check_error(Context_val(context),r);
  r = krb5_verify_init_creds(Context_val(context), &creds, serv, kt, &cc, NULL);
  krb5_check_error(Context_val(context),r);
  value v = caml_alloc_custom(&krb5_creds_ops, sizeof(krb5_creds), 0, 1);
  *Creds_val(v) = creds;
  CAMLreturn(v);
}

CAMLprim value ml_krb5_get_init_creds_password(value* args, int nb) {
  return(mx_krb5_get_init_creds_password(args[0],args[1],args[2],args[3],
					 args[4],args[5],args[6]));
}

CAMLprim value mx_krb5_get_init_creds_keytab(value context,
					     value principal,
					     value server,
					     value keytab,
					     value ccache,
					     value tkt_service) {
  CAMLparam5(context,principal,server,keytab,ccache);
  CAMLxparam1(tkt_service);
  krb5_creds creds;
  const char* tkt = NULL;
  if (Is_some(tkt_service)) tkt = String_val(Some_val(tkt_service));
  krb5_principal serv = NULL;
  if (Is_some(server)) serv = Principal_val(Some_val(server));
  krb5_keytab kt = NULL;
  kt = Keytab_val(keytab);
  krb5_ccache cc = NULL;
  if (Is_some(ccache)) cc = Ccache_val(Some_val(ccache));

  krb5_error_code r = krb5_get_init_creds_keytab(Context_val(context),
						 &creds,
						 Principal_val(principal),
						 kt, 0, tkt, NULL);
  krb5_check_error(Context_val(context),r);
  r = krb5_verify_init_creds(Context_val(context), &creds, serv, kt, &cc, NULL);
  krb5_check_error(Context_val(context),r);
  value v = caml_alloc_custom(&krb5_creds_ops, sizeof(krb5_creds), 0, 1);
  *Creds_val(v) = creds;
  CAMLreturn(v);
}

CAMLprim value ml_krb5_get_init_creds_keytab(value* args, int nb) {
  return(mx_krb5_get_init_creds_keytab(args[0],args[1],args[2],args[3],
				       args[4],args[5]));
}


CAMLprim value ml_krb5_creds_data(value creds) {
  CAMLparam1(creds);
  CAMLreturn(ml_krb5_string_data(Creds_val(creds)->ticket));
}
