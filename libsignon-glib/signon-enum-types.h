


#ifndef __SIGNON_ENUM_TYPES_H__
#define __SIGNON_ENUM_TYPES_H__
#include <glib-object.h>

G_BEGIN_DECLS
/* enumerations from "signon-auth-session.h" */
GType signon_session_data_ui_policy_get_type (void) G_GNUC_CONST;
#define SIGNON_TYPE_SESSION_DATA_UI_POLICY (signon_session_data_ui_policy_get_type())
/* enumerations from "signon-identity-info.h" */
GType signon_identity_type_get_type (void) G_GNUC_CONST;
#define SIGNON_TYPE_IDENTITY_TYPE (signon_identity_type_get_type())
/* enumerations from "signon-errors.h" */
GType signon_error_get_type (void) G_GNUC_CONST;
#define SIGNON_TYPE_ERROR (signon_error_get_type())
G_END_DECLS

#endif /* __SIGNON_ENUM_TYPES_H__ */



