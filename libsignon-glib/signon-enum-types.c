


#include "signon-enum-types.h"
#include "signon-identity-info.h"
#include "signon-auth-session.h"
#define g_intern_static_string(s) (s)

/* enumerations from "signon-auth-session.h" */
GType
signon_session_data_ui_policy_get_type (void)
{
  static GType etype = 0;
  if (etype == 0) {
    static const GEnumValue values[] = {
      { SIGNON_POLICY_DEFAULT, "SIGNON_POLICY_DEFAULT", "default" },
      { SIGNON_POLICY_REQUEST_PASSWORD, "SIGNON_POLICY_REQUEST_PASSWORD", "request-password" },
      { SIGNON_POLICY_NO_USER_INTERACTION, "SIGNON_POLICY_NO_USER_INTERACTION", "no-user-interaction" },
      { SIGNON_POLICY_VALIDATION, "SIGNON_POLICY_VALIDATION", "validation" },
      { 0, NULL, NULL }
    };
    etype = g_enum_register_static (g_intern_static_string ("SignonSessionDataUiPolicy"), values);
  }
  return etype;
}

/* enumerations from "signon-identity-info.h" */
GType
signon_identity_type_get_type (void)
{
  static GType etype = 0;
  if (etype == 0) {
    static const GFlagsValue values[] = {
      { SIGNON_IDENTITY_TYPE_OTHER, "SIGNON_IDENTITY_TYPE_OTHER", "other" },
      { SIGNON_IDENTITY_TYPE_APP, "SIGNON_IDENTITY_TYPE_APP", "app" },
      { SIGNON_IDENTITY_TYPE_WEB, "SIGNON_IDENTITY_TYPE_WEB", "web" },
      { SIGNON_IDENTITY_TYPE_NETWORK, "SIGNON_IDENTITY_TYPE_NETWORK", "network" },
      { 0, NULL, NULL }
    };
    etype = g_flags_register_static (g_intern_static_string ("SignonIdentityType"), values);
  }
  return etype;
}

#define __SIGNON_ENUM_TYPES_C__



