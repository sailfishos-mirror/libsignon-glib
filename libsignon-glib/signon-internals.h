/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _SIGNONINTERNALS_H_
#define _SIGNONINTERNALS_H_

#ifndef SIGNON_TRACE
#define SIGNON_TRACE
#endif

#ifdef SIGNON_TRACE
    #define DEBUG(format...) g_debug (G_STRLOC ": " format)
#else
    #define DEBUG(...) do {} while (0)
#endif

#include "signon-identity.h"
#include "signon-auth-session.h"
#include "signon-security-context.h"

G_BEGIN_DECLS

struct _SignonIdentityInfo
{
    gint id;
    gchar *username;
    gchar *secret;
    gchar *caption;
    gboolean store_secret;
    GHashTable *methods;
    gchar **realms;
    GList *access_control_list;
    gint type;
};

struct _SignonSecurityContext
{
    gchar *system_context;
    gchar *application_context;
};

#define SIGNOND_SERVICE_PREFIX "com.google.code.AccountsSSO.SingleSignOn"
#define SIGNON_DBUS_ERROR_PREFIX SIGNOND_SERVICE_PREFIX ".Error."
#define SIGNOND_DAEMON_OBJECTPATH "/com/google/code/AccountsSSO/SingleSignOn"

/*
 * Common server/client sides error names and messages
 * */
#define SIGNOND_UNKNOWN_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "Unknown"
#define SIGNOND_INTERNAL_SERVER_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "InternalServer"
#define SIGNOND_INTERNAL_COMMUNICATION_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "InternalCommunication"
#define SIGNOND_PERMISSION_DENIED_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "PermissionDenied"
#define SIGNOND_METHOD_OR_MECHANISM_NOT_ALLOWED_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "MethodOrMechanismNotAllowed"
#define SIGNOND_ENCRYPTION_FAILED_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "EncryptionFailed"
#define SIGNOND_METHOD_NOT_KNOWN_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "MethodNotKnown"
#define SIGNOND_SERVICE_NOT_AVAILABLE_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "ServiceNotAvailable"
#define SIGNOND_INVALID_QUERY_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "InvalidQuery"
#define SIGNOND_METHOD_NOT_AVAILABLE_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "MethodNotAvailable"
#define SIGNOND_IDENTITY_NOT_FOUND_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "IdentityNotFound"
#define SIGNOND_STORE_FAILED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "StoreFailed"
#define SIGNOND_REMOVE_FAILED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "RemoveFailed"
#define SIGNOND_SIGNOUT_FAILED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "SignOutFailed"
#define SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "IdentityOperationCanceled"
#define SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "CredentialsNotAvailable"
#define SIGNOND_REFERENCE_NOT_FOUND_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "ReferenceNotFound"
#define SIGNOND_MECHANISM_NOT_AVAILABLE_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "MechanismNotAvailable"
#define SIGNOND_MISSING_DATA_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "MissingData"
#define SIGNOND_INVALID_CREDENTIALS_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "InvalidCredentials"
#define SIGNOND_NOT_AUTHORIZED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "NotAuthorized"
#define SIGNOND_WRONG_STATE_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "WrongState"
#define SIGNOND_OPERATION_NOT_SUPPORTED_ERR_NAME \
    SIGNON_DBUS_ERROR_PREFIX "OperationNotSupported"
#define SIGNOND_NO_CONNECTION_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "NoConnection"
#define SIGNOND_NETWORK_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "Network"
#define SIGNOND_SSL_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "Ssl"
#define SIGNOND_RUNTIME_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "Runtime"
#define SIGNOND_SESSION_CANCELED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "SessionCanceled"
#define SIGNOND_TIMED_OUT_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "TimedOut"
#define SIGNOND_USER_INTERACTION_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "UserInteraction"
#define SIGNOND_OPERATION_FAILED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "OperationFailed"
#define SIGNOND_TOS_NOT_ACCEPTED_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "TOSNotAccepted"
#define SIGNOND_FORGOT_PASSWORD_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "ForgotPassword"
#define SIGNOND_INCORRECT_DATE_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "IncorrectDate"
#define SIGNOND_USER_ERROR_ERR_NAME SIGNON_DBUS_ERROR_PREFIX "User"

G_GNUC_INTERNAL
SignonIdentityInfo *
signon_identity_info_new_from_variant (GVariant *variant);

G_GNUC_INTERNAL
GVariant *
signon_identity_info_to_variant (const SignonIdentityInfo *self);

G_GNUC_INTERNAL
SignonSecurityContext *
signon_security_context_new_from_variant (GVariant *variant);

G_GNUC_INTERNAL
GVariant *
signon_security_context_to_variant (const SignonSecurityContext *self);

G_GNUC_INTERNAL
void signon_identity_info_set_methods (SignonIdentityInfo *self,
                                       const GHashTable *methods);

G_GNUC_INTERNAL
void signon_auth_session_set_id(SignonAuthSession* self,
                                gint32 id);

G_END_DECLS

#endif

